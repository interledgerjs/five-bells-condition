const webpack = require('webpack')
const UglifyJsPlugin = webpack.optimize.UglifyJsPlugin;

module.exports = {
  entry: './index.js',
  output: {
    path: __dirname + '/dist',
    filename: 'index.js',
    library: 'FiveBellsCondition',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  progress: true,
  module: {
    loaders: [
      { test: /\.js$/, exclude: /node_modules/, loader: 'babel'},
      { test: /\.json$/, loader: 'json-loader' }
    ]
  },
  node: {
    fs: "empty"
  },
  plugins: [
    new UglifyJsPlugin()
  ]
}
