# misp-takedown

A curses-style interface for generating automatic takedown notifications through RT/RTIR using [MISP](https://github.com/MISP/MISP) events as input.

## Disclaimer

This code is a surprisingly well working result of an experiment. However, the code needs improvements here and there.
Also, the installation process regarding urlabuse, uwhoisd, MISP and RT/RTIR is not the most straight forward.
We'd be happy to find contributors for code improvements and installation documentation. Both could be part of an internship at CIRCL. Reach out if you are interested.

## Requirements

misp-takedown requires a MISP instance (API access) and:

- [urlabuse](https://github.com/CIRCL/url-abuse)
- [uwhoisd](https://github.com/Rafiot/uwhoisd) for lookup of abuse email addresses.
- [RT/RTIR](https://bestpractical.com/rtir/)

## Templates included

A series of notification templates are included, such as:

- [Compromised website](./templates/compromised_website.tmpl-sample)
- [Malicious files hosted](./templates/malicious_files_hosted.tmpl-sample)

It can be easily extended to match your abuse notification processes and/or templates.

## Demo

What it looks like: [video screencast](https://www.youtube.com/watch?v=LsZA9YWDodQ)

## License

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2017, 2018 Sascha Rommelfangen
* Copyright (C) 2017, 2018 CIRCL - Computer Incident Response Center Luxembourg
