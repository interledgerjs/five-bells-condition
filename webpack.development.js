/* eslint-disable strict, no-console, object-shorthand */

'use strict'

const TerserPlugin = require('terser-webpack-plugin')

module.exports = {
  devtool: 'inline-source-map',
  optimization: {
    minimizer: [
      new TerserPlugin({
        test: /vendor/
      }),
      new TerserPlugin({
        test: /^((?!(vendor)).)*.js$/
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
