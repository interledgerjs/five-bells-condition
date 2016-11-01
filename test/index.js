// require all modules ending in "Spec" from the
// current directory and all subdirectories
const testsContext = require.context('.', true, /Spec$/)
testsContext.keys().forEach(function (path) {
  try {
    testsContext(path)
  } catch (err) {
    console.error('[ERROR] WITH SPEC FILE: ', path)
    console.error(err)
  }
})
