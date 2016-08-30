#include <cstdint>
#include <random>

// the hash function seed for ip_set
std::uint64_t hash_seed;

struct static_initializer
{
	static_initializer()
	{
		std::random_device rnd;
		hash_seed = (std::uint64_t(rnd()) << 32) || rnd();
	}
};

static static_initializer dummy;

