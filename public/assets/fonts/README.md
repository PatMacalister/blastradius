# Bundled fonts

Three families are redistributed here as `.woff2` subsets. All are licensed under the SIL
Open Font License 1.1, which permits redistribution — including bundled inside another
work — on the condition that the licence and copyright notice travel with the font files.
That is what the `OFL-*.txt` files next to them are for. They are not optional, and they are
not covered by this project's own Apache-2.0 licence: the fonts keep their own terms.

| Family | Files | Copyright | Licence |
|---|---|---|---|
| Archivo | `archivo-latin-{400,500,600}-normal.woff2` | 2020 The Archivo Project Authors ([Omnibus-Type](https://github.com/Omnibus-Type/Archivo)) | [OFL-Archivo.txt](OFL-Archivo.txt) |
| Instrument Serif | `instrument-serif-latin-400-{normal,italic}.woff2` | 2022 The Instrument Serif Project Authors ([Instrument](https://github.com/Instrument/instrument-serif)) | [OFL-InstrumentSerif.txt](OFL-InstrumentSerif.txt) |
| JetBrains Mono | `jetbrains-mono-latin-{400,700}-normal.woff2` | 2020 The JetBrains Mono Project Authors ([JetBrains](https://github.com/JetBrains/JetBrainsMono)) | [OFL-JetBrainsMono.txt](OFL-JetBrainsMono.txt) |

Self-hosted rather than loaded from a CDN, deliberately. The landing page for a tool about
credential reach should not hand every visitor's IP address and user agent to a third party
in order to render its own headings.

If you add a weight or a family, add its licence in the same commit. The obligation attaches
when the file is redistributed, which is the moment it is committed — not later.
