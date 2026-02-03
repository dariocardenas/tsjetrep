const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = (env, argv) => ({
    devServer: {
        static: {
            directory: path.join(__dirname, 'dist'),
        },
        port: 3000,
    },
    entry: {
        trep: {
            import: './src/trep.js',
        }
    },
    module: {
        rules: [
            {
                test: /\.html$/,
                type: 'asset/source',
            },
            {
                test: /\.css$/,
                type: 'asset/source',
            },
            {
                test: /\.xml$/,
                type: 'asset/source',
            }
        ]
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: argv.mode === 'production' ? '[name].[contenthash].js' : '[name].js',
    },
    plugins: [
        new HtmlWebpackPlugin({
            chunks: ['trep'],
            favicon: './src/favicon.ico',
        })
    ]
})