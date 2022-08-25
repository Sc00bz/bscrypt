# bscrypt
A cache hard password hash/KDF

## Why Cache Hard

Cache hard algorithms are better than memory hard algorithms at shorter run times.
Basically cache hard algorithms forces GPUs to use 1/4 to 1/16 of the memory bandwidth because of the large bus width (commonly 256 to 1024 bits).
Another way to look at it is memory transactions vs bandwidth.
Also the low latency of L2 cache on CPUs and the 8 parallel look ups let's us make a lot of random reads.
With memory hard algorithms, there is a point where doubling the memory quarters a GPU attacker's speed.
There then is a point at which a memory hard algorithm will overtake a cache hard algorithm.
Cache hard algorithms don't care that GPUs will get ~100% utilization of memory transactions because it's already very limiting.

## Settings

* `m` (`memoryKiB`)
* `t` (`iterations`)
* `p` (`parallelism`)

Set `m` to the largest per core cache size.
For current CPUs, this is L2 cache and commonly 256 KiB, 512 KiB, 1 MiB, or 1.25 MiB per core.
You shouldn't currently go less than 128 KiB.
When in doubt use `m=256` (256 KiB).

If doing server side, then set `p` to 1.
But if you set up a queuing system the set `p` to number of cores or less.
You may want to benchmark different values of `p` with normal other workloads.
Too find the best `p`.

Now set `t` to at least `1900000 / (1024 * m * p)`.
If you want it to be stronger because this is likely a few milliseconds change 1'900'000 to 19'000'000.
This will limit GPU attackers to <1 KH/s/GPU.
Which is good for encryption.
Note that next gen GPUs are launching around November 2022 and these are just bare minimums for `t`.
I recommend using settings that are at least twice as hard on current hardware to account for future advances.
Just so you have time to upgrade settings so that old settings are still <10 KH/s/GPU.

### Easy Settings
Just use `m=256`, `t=80`, `p=1` that should still be good in 2030.

Looking at historical GPU memory transaction rates and using an exponential trend line for AMD it's still good in 2043 and Nvidia it's still good in 2034.
This assumes GPU cache sizes aren't like 10x higher per SM or whatever by then.

## "Not BLAKE2b"

Not a BLAKE2b mix calculation.
There is no message and the rotates were changed from 32,24,16,63 to 8,1,16,11,40,32.
These were found to give a faster mix by a program that checked 2 any rotates, 3 byte rotates, and a 32 bit rotate.
This was picked out of several equivalent ones because it looked similar to the "best" 4 rotates.
These are 8,1,24,32 that are 1 any rotate, 2 byte rotates, and a 32 bit rotate.

Related: https://twitter.com/Sc00bzT/status/1461894336052973573

I went with the 6 rotates because it mixed faster.
I was going to do either:

* 2 rounds of 6 rotates
* 3 rounds of 4 rotates

Oh "3 rounds of 4 rotates" has a "coverage" of 87.5% and I believe "2 rounds of 6 rotates" has a "coverage" of 100%.
I need to check this it's been a almost a year since I looked at the data.
"Coverage" is the percent of bits from the block that have affected other bits.
You need 1'024 variables representing the 1'024 bits in the block.
Each variable has 1'024 bits representing which bit from the block has influenced its value.
You rotate those and OR them together instead of add and XOR.
Then count the bits that are set.
This may not be the best way to check for the best rotates.
Also addition influences higher bits which this doesn't check for.
