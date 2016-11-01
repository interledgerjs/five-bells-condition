const webpack = require('webpack')
const path = require('path')
const UglifyJsPlugin = webpack.optimize.UglifyJsPlugin

module.exports = {
  devtool: 'inline-source-map',
  entry: ['babel-polyfill', './index.js'],
  output: {
    path: path.join(__dirname, 'dist'),
    filename: 'index.js',
    library: 'FiveBellsCondition',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  module: {
    loaders: [
      { test: /\.js$/, exclude: /node_modules/, loader: 'babel' },
      { test: /\.json$/, loader: 'json-loader' }
    ]
  },
  node: {
    fs: 'empty'
  },
  plugins: [
    new UglifyJsPlugin()
  ]
}
