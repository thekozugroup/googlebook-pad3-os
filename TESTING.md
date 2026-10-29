# Source verification

From the checkout root, use a local temporary directory outside cloud sync:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -p 'test_*.py'
```

Some checks need local SDKs, compiler tools, pinned images, or certificates and
will skip or fail when those private build inputs are absent. Inspect the results.
These checks do not establish that the tablet can boot or that the pen works.
The source exporter tests use synthetic nonmaterial credentials only.
Owner PIN tests and device capture output are excluded from public source.

Device checks require an explicit `--serial` or `ANDROID_SERIAL` for
`stability_probe.py`. Keep its output private and outside the public source tree.
Flashing, DSU activation, rebooting and hardware tests require a separate procedure.
