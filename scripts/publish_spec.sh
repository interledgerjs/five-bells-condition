#!/bin/sh

command -v xml2rfc || pip install xml2rfc
git clone git@github.com:interledger/five-bells-condition.git --branch gh-pages --single-branch web
cd web
xml2rfc ../docs/spec.xml --html -o spec.html
xml2rfc ../docs/spec.xml --text -o spec.txt
git commit -am 'docs(spec): update spec'
git push
