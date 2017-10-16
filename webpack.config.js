const webpack = require('webpack')
const path = require('path')

module.exports = {
  devtool: '#source-map',
  entry: ['./index.js'],
  output: {
    path: path.join(__dirname, 'dist'),
    filename: 'index.js',
    library: 'FiveBellsCondition',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  module: {
    loaders: [
      { test: /\.js$/, exclude: /node_modules/, loader: 'babel-loader' },
      { test: /\.json$/, loader: 'json-loader' }
    ]
  },
  node: {
    fs: 'empty'
  },
  plugins: [
    new webpack.optimize.UglifyJsPlugin({
      compress: {
        warnings: false
      },
      output: {
        comments: false
      },
      sourceMap: true
    }),
    new webpack.LoaderOptionsPlugin({
      debug: false,
      minimize: true
    })
  ]
}
