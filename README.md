# relibc for redox-rpi (unofficial fork)

This repository is an **unofficial, AI-assisted fork** of
[relibc](https://gitlab.redox-os.org/redox-os/relibc), the C library of the
Redox OS™ operating system. It holds the relibc changes of
[redox-rpi](https://github.com/redox-rpi/redox-rpi), which brings Redox OS to
the Raspberry Pi 3B+ and Zero 2 W (aarch64).

It is not affiliated with or endorsed by the Redox OS project. Redox does not
accept AI-generated contributions, so nothing from here is submitted
upstream. Report problems with this fork in the
[redox-rpi issues](https://github.com/redox-rpi/redox-rpi/issues), not to
the Redox OS project.

- **Original:** https://gitlab.redox-os.org/redox-os/relibc
  (GitHub mirror: https://github.com/redox-os/relibc)

## Branches

This branch, `main`, only holds this README. The code is on these branches:

| Branch | What it is |
|---|---|
| [`upstream`](../../tree/upstream) | The upstream relibc commit that redox-rpi pins in [`config/upstream.lock`](https://github.com/redox-rpi/redox-rpi/blob/main/config/upstream.lock), unchanged |
| [`redox-rpi`](../../tree/redox-rpi) | `upstream` plus our patches: what redox-rpi images are built with |
| `exp/<name>` | One experiment each, on top of `redox-rpi`, for example `exp/ldso-diagnostics` |

`git format-patch upstream..redox-rpi` gives the patch files again. The
build itself uses the patch files in
[redox-rpi/patches/relibc/](https://github.com/redox-rpi/redox-rpi/tree/main/patches/relibc)
and experiments in
[redox-rpi/patches/experiments/](https://github.com/redox-rpi/redox-rpi/tree/main/patches/experiments);
`scripts/relibc-checkout.sh` there checks out the same state.

## Working on it

Read [CONTRIBUTING.md](https://github.com/redox-rpi/redox-rpi/blob/main/CONTRIBUTING.md)
of redox-rpi first. The relibc tasks have the label
[`topic:relibc`](https://github.com/redox-rpi/redox-rpi/issues?q=is%3Aopen+label%3Atopic%3Arelibc),
the state is in [docs/topics/relibc.md](https://github.com/redox-rpi/redox-rpi/blob/main/docs/topics/relibc.md).

## License

relibc is licensed under the MIT license, see `LICENSE` on the
[`redox-rpi`](../../blob/redox-rpi/LICENSE) branch. Our changes are under the
same license.
