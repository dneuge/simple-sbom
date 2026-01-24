# Simple SBOM

You want to keep track, semi-machine-readable, of your project's dependencies and licenses but need to manually edit the file because there's no proper package management for your project and standard SBOM tools don't provide the output you're looking for? Then maybe this little project can help, which was created to keep track of a C project with manually managed dependencies.

This project provides an XSD (XML Schema Definition) to manually create your own SBOM, describing your own project as well as its dependencies, authors, licenses and trademarks.

More documentation and some tooling will follow; the project has only been started but published early to already be easily downloadable as a sub-module. The format/XSD is highly unfinished; please don't rely on the format just yet.

Official repositories are hosted on [Codeberg](https://codeberg.org/dneuge/simple-sbom) and [GitHub](https://github.com/dneuge/simple-sbom). Both locations are kept in sync and can be used to submit pull requests but issues are only tracked on [Codeberg](https://codeberg.org/dneuge/simple-sbom/issues) to gather them in a single place. Please note that this project has a strict "no AI" policy affecting all contributions incl. issue reports (see below, AI is not permitted to be used for *any* kind of contribution).

## License

All sources and original files of this project are provided under [MIT license](LICENSE.md), unless declared otherwise
(e.g. by source code comments).

### Note on the use of/for AI

Usage for AI training is subject to individual source licenses, there is no exception. This generally means that proper
attribution must be given and disclaimers may need to be retained when reproducing relevant portions of training data.
When incorporating source code, AI models generally become derived projects. As such, they remain subject to the
requirements set out by individual licenses associated with the input used during training. When in doubt, all files
shall be regarded as proprietary until clarified.

Unless you can comply with the licenses of this project you obviously are not permitted to use it for your AI training
set. Although it may not be required by those licenses, you are additionally asked to make your AI model publicly
available under an open license and for free, to play fair and contribute back to the open community you take from.

AI tools are not permitted to be used for contributions to this project. The main reason is that, as of time of writing,
no tool/model offers traceability nor can today's AI models understand and reason about what they are actually doing.
Apart from potential copyright/license violations the quality of AI output is doubtful and generally requires more
effort to be reviewed and cleaned/fixed than actually contributing original work. Contributors will be asked to confirm
and permanently record compliance with these guidelines.
