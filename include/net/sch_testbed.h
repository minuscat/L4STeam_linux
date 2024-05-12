/* This file contains our logic for reporting drops to traffic analyzer
 * and is used by our patched versions of the different schedulers
 * we are using.
 *
 * It is only used for our testbed, and for a final implementation it
 * should not be included.
 */
#include <net/inet_ecn.h>

/* This constant defines whether to include drop/queue level report and other
 * testbed related stuff we only want while developing our scheduler.
 */
/* we store drops in 5 bits */
#define DROPS_M 2
#define DROPS_E 3

/* we store queue length in 11 bits */
#define QDELAY_M 7
#define QDELAY_E 4

/* Decode float value
 *
 * fl: Float value
 * m_b: Number of mantissa bits
 * e_b: Number of exponent bits
 */
static inline u32 fl2int(u32 fl, u32 m_b, u32 e_b)
{
	const u32 m_max = 1 << m_b;

	fl &= ((m_max << e_b) - 1);

	if (fl < (m_max << 1)) {
		return fl;
	} else {
		return (((fl & (m_max - 1)) + m_max) << ((fl >> m_b) - 1));
	}
}

/* Encode integer value as float value
 * The value will be rounded down if needed
 *
 * val: Value to convert into a float
 * m_b: Number of mantissa bits
 * e_b: Number of exponent bits
 * r: Variable where the remainder will be stored
 */
static inline u32 int2fl(u32 val, u32 m_b, u32 e_b, u32 *r)
{
	u32 len, exponent, mantissa;
	const u32 max_e = (1 << e_b) - 1;
	const u32 max_m = (1 << m_b) - 1;
	const u32 max_fl = ((max_m << 1) + 1) << (max_e - 1);
	*r = 0;

	if (val < (1 << (m_b + 1))) {
		/* possibly only first exponent included, no encoding needed */
		return val;
	}

	if (val >= max_fl) {
		/* avoid overflow */
		*r = val - max_fl;
		return (1 << (m_b + e_b)) - 1;
	}

	/* number of bits without leading 1 */
	len = (sizeof(u32) * 8) - __builtin_clz(val) - 1;

	exponent = len - m_b;
	mantissa = (val >> exponent) & ((1 << m_b) - 1);
	*r = val & ((1 << exponent) - 1);

	return ((exponent + 1) << m_b) | mantissa;
}

struct testbed_metrics {
	u16	drops_ecn;
	u16	drops_nonecn;
};

static inline void testbed_metrics_init(struct testbed_metrics *testbed)
{
	testbed->drops_ecn = 0;
	testbed->drops_nonecn = 0;
}

static inline void testbed_inc_drop_count(struct testbed_metrics *testbed,
					  u8 ect)
{
	if (ect == INET_ECN_NOT_ECT)
		testbed->drops_nonecn++;
	else
		testbed->drops_ecn++;
}

static inline u32 testbed_write_drops(struct testbed_metrics *testbed, u8 tos)
{
	u32 drops, remainder;
	if (tos & INET_ECN_MASK) {
		drops = int2fl(testbed->drops_ecn, DROPS_M, DROPS_E, &remainder);
		testbed->drops_ecn = (__force __u16)remainder;
	} else {
		drops = int2fl(testbed->drops_nonecn, DROPS_M, DROPS_E, &remainder);
		testbed->drops_nonecn = (__force __u16)remainder;
	}
	return drops;
}

static inline void testbed_add_metrics_ipv4(struct sk_buff *skb,
					    struct testbed_metrics *testbed,
					    u16 qdelay)
{
	struct iphdr *iph = ip_hdr(skb);
	u16 drops, id;
	u32 check;

	check = ntohs((__force __be16)iph->check) + ntohs(iph->id);
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;
	drops = (__force __u16)testbed_write_drops(testbed, iph->tos);
	/* use upper 5 bits in id field to store number of drops before
	 * the current packet
	 */
	id = qdelay | (drops << 11);

	check -= id;
	check += check >> 16; /* adjust carry */

	iph->id = htons(id);
	iph->check = (__force __sum16)htons(check);
}

/* Add metrics used by traffic analyzer to packet before dispatching.
 * qdelay is the time in units of 1024 us that the packet spent in the queue.*/
static inline void testbed_add_metrics(struct sk_buff *skb,
				       struct testbed_metrics *testbed,
				       u32 qdelay_us)
{
	int wlen = skb_network_offset(skb);
	u32 qdelay_remainder;
	u16 qdelay;

	/* qdelay_remainder includes quantization error is not used right now */
	qdelay = (__force __u16)int2fl(qdelay_us, QDELAY_M, QDELAY_E, &qdelay_remainder);

	/* TODO: IPv6 support using flow label (and increase resolution?) */
	switch (skb_protocol(skb, true)) {
	case htons(ETH_P_IP):
		wlen += sizeof(struct iphdr);
		if (!pskb_may_pull(skb, wlen) ||
		    skb_try_make_writable(skb, wlen))
			break;

		testbed_add_metrics_ipv4(skb, testbed, qdelay);
		break;
	case htons(ETH_P_IPV6):
		wlen += sizeof(struct ipv6hdr);
		if (!pskb_may_pull(skb, wlen) ||
		    skb_try_make_writable(skb, wlen))
			break;
		break;
	default:
		break;
	}
}
