# pgextwin — Windows PostgreSQL extensions

[日本語](README_ja.md) | English

pgextwin provides **unofficial Windows x64 binaries** for PostgreSQL extensions. It is an independent community project, not an official distribution from the upstream extension authors, PostgreSQL, or EDB.

## Find and download

Browse the [pgextwin catalog](https://pgextwin.github.io/website/en/) to find the **17 extensions** in the project, their published versions, PostgreSQL compatibility, and download links. Inclusion in the project does not mean a new upstream version has already been published.

You can also use the [GitHub repositories](https://github.com/orgs/pgextwin/repositories) and open each extension's **Releases** page for the latest published package and its release notes.

## Compatibility and installation

- Platform: **Windows x64**. Packages have been published for PostgreSQL **14–18**; availability varies by extension and Release.
- PostgreSQL 14 reaches the end of community support on **November 12, 2026**. Existing files may remain available as historical downloads after that date.
- Download the ZIP for **your exact PostgreSQL major version**. Do not mix files compiled for different majors.
- Follow the extension's README and upstream documentation for file placement and setup. Some extensions require preload configuration and a restart; others use additional executables or different installation steps.
- Back up relevant data and test in a non-production environment first.

## Verify downloaded files

Each Release includes **SHA256SUMS.txt** for file integrity checks. Some Releases also provide SPDX SBOMs, vulnerability reports, and signed attestations. Check the actual assets on the Release page; these materials do not guarantee that a package has no vulnerabilities.

## Upstream projects and licenses

Each upstream project documents its own SQL interface, configuration, and limitations. See the upstream links in the catalog and the license files included with each package. pgextwin does not claim upstream endorsement.

[日本語カタログ](https://pgextwin.github.io/website/ja/) · [Report a problem](https://github.com/pgextwin/build/issues)
