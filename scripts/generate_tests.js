'use strict'

const fs = require('fs')
const path = require('path')
const Mustache = require('mustache')

// Disable escaping
Mustache.escape = a => a

const testsuitePath = path.resolve(__dirname, '../testsuite')
const mochaPath = path.resolve(__dirname, '../test')

const testTemplate = fs.readFileSync(path.resolve(__dirname, 'test.template.js'), 'utf8')

for (const suite of fs.readdirSync(testsuitePath)) {
  const suitePath = path.resolve(testsuitePath, suite)

  const cases = fs.readdirSync(suitePath).map((name) => {
    const testPath = path.resolve(suitePath, name)
    const testData = require(testPath)

    return Object.assign({}, testData, {
      name,
      json: JSON.stringify(testData.json)
    })
  })

  const suiteData = {
    suite,
    cases
  }

  const specFilePath = path.resolve(mochaPath, 'generated_' + suite + 'Spec.js')
  fs.writeFileSync(specFilePath, Mustache.render(testTemplate, suiteData))
}
