/* eslint-disable strict, no-console, object-shorthand */

'use strict'

const TerserPlugin = require('terser-webpack-plugin')

module.exports = {
  devtool: 'inline-source-map',
  optimization: {
    minimizer: [
      new TerserPlugin({
        test: /vendor/,
        sourceMap: false
      }),
      new TerserPlugin({
        test: /^((?!(vendor)).)*.js$/,
        sourceMap: false
      })
    ],
    splitChunks: {
      cacheGroups: {
        commons: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all'
        }
      }
    }
  }
}
