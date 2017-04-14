# misp-takedown

A curses-style interface for automatic takedown notification based on [MISP](https://github.com/MISP/MISP) events.

## Requirements

misp-takedown requires a MISP instance (API access) and:

- [urlabuse](https://github.com/CIRCL/url-abuse)
- [uwhoisd](https://github.com/Rafiot/uwhoisd) for lookup of abuse email addresses.

## Templates included

A series of templates notification are included like:

- [Compromised website](./templates/compromised_website.tmpl-sample)
- [Malicious files hosted](./templates/malicious_files_hosted.tmpl-sample)

It can be easily extended to match your abuse notification processes or/and templates.

## Demo

How it looks like: [video screencast](https://www.youtube.com/watch?v=LsZA9YWDodQ)
