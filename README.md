# iggypopi.github.io

Source of [iggypopi.github.io](https://iggypopi.github.io/), Igor Stepansky's security-research blog: vulnerability writeups (CVEs in AI serving frameworks, the Linux kernel, Kubernetes tooling and CI/CD), conference talks, and tools.

Built with [Jekyll](https://jekyllrb.com/) and the [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) theme, deployed to GitHub Pages by the workflow in `.github/workflows/`. Theme assets are self-hosted (the `assets/lib` submodule) and the site makes no third-party requests.

## Layout

- `_posts/`: the writeups. Research posts carry `cve`, `cvss` and `component` front matter; the Research page, the counters and the badges are generated from it.
- `_data/talks.yml`, `_data/tools.yml`, `_data/home_intro.yml`: the Talks timeline, the Tools page and the home intro.
- `_plugins/content-checks.rb`: build-time checks for post front matter and house style.

## License

The site code is MIT licensed, see `LICENSE`. Each post carries its own license note at the end.
