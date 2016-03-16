# Builidng the RFC documents

## xml2rfc

This spec is written using the xml2rfc tools provided at http://tools.ietf.org/tools/

An online version is available at: http://xml2rfc.ietf.org/

## Get Started

xml2rfc can be installed using the Python package manager pip.

`pip install xml2rfc`

If that doesn't work start looking for help here: http://pypi.python.org/pypi/xml2rfc/

To generate the RFC use:

`xml2rfc spec.xml -o build/spec.txt --text`

or

`xml2rfc spec.xml -o build/spec.html --html`