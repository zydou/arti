# How to run Criterion benchmarks

Benchmark results obtained with Criterion can be dependent on many external factors that have nothing to do with the
actual benched function. See [Criterion FAQ](https://bheisler.github.io/criterion.rs/book/faq.html#i-made-no-change-to-my-source-and-criterionrs-reports-a-large-change-in-performance-why)
on the subject.

To minimize the noise a few extra steps can be undertaken.

- Pin the benchmark to a specific CPU core. This avoids measuring thread migration.
- Fix the CPU frequency, especially for cycle measurement based on clock ticks (see
  [criterion-cycles-per-byte](https://github.com/wainwrightmark/criterion-cycles-per-byte/blob/master/README.md) crate
  for more info).

## Get the CPU frequency range and default governor

To get the frequency range and default governor of your CPU, you can run the `cpupower` command.
This will enable you to pick an allowed benchmark frequency and restore the default settings after the benchmarks.

```bash
$ cpupower -c 0 frequency-info -p
analyzing CPU 0:
  current policy: frequency should be within 400 MHz and 4.20 GHz.
                  The governor "powersave" may decide which speed to use
                  within this range.
```

## Run the benchmarks

Use the `cpupower` and `taskset` commands to set up and run the benchmarks after adjusting the frequencies to your CPU.
The following example sets the benchmark frequency to the maximum, but the most important thing is to keep it constant.

```bash
# Change those values for your CPU
MIN=400MHz      # The default min frequency
MAX=4.2GHz      # The default max frequency
SET_FREQ=4.2GHz # The benchmark frequency
CRATE=tor-proto # The target crate (will run all benchmarks of that crate)

# Set the benchmark frequency and governor
sudo cpupower -c 0 frequency-set -d $SET_FREQ -u $SET_FREQ -g performance
# Pin the benchmark to core 0
taskset -c 0 cargo bench -p $CRATE --all-features
# Restore default values
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave
```
