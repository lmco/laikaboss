const path = require('path');
const HTMLWebpackPlugin = require('html-webpack-plugin');
const { VueLoaderPlugin } = require('vue-loader');
const { HotModuleReplacementPlugin, DefinePlugin } = require('webpack');



module.exports = env => {
    return {
        mode: env && env.MODE ? env.MODE : 'development',
        entry: path.join(__dirname, './src/app.js'),
        output: {
            path: path.join(__dirname, './dist/'),
            filename: '[name].[hash].bundled.js',
            publicPath: env && env.PUBLIC_PATH ? env.PUBLIC_PATH : '/'
        },
        devServer: {
            port: 8000,
            host: '127.0.0.1',
            hot: true,
            // open: true,
            historyApiFallback: true,
            contentBase: path.join(__dirname, './dist/'),
            headers: {
                "Access-Control-Allow-Origin": "*",
            }
        },
        module: {
            rules: [
                {
                    test: /\.js$/,
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env']
                    }
                },
                {
                    test: /\.vue$/,
                    loader: 'vue-loader'
                },
                {
                    test: /\.css$/,
                    use: [
                        'vue-style-loader',
                        'css-loader'
                    ]
                },
                {
                    test: /\.(png|svg|jpe?g|gif)$/,
                    use: [
                        {
                            loader: 'url-loader',
                            options: {
                                fallback: 'file-loader',
                                limit: 8192,
                                publicPath: env && env.PUBLIC_PATH ? env.PUBLIC_PATH + '/' : '/'
                            },
                        }
                    ]
                }
            ]
        },
        plugins: [
            new HotModuleReplacementPlugin(),
            new VueLoaderPlugin(),
            new HTMLWebpackPlugin({
                showErrors: true,
                cache: false,
                title: 'Laikaboss',
                favicon: 'favicon.ico',
                template: path.join(__dirname, 'index.html')
            }),
            new DefinePlugin({
                "process.env.REST_API_URL": env && env.REST_API_URL ? JSON.stringify(env.REST_API_URL) : JSON.stringify("http://127.0.0.1:8123"),
                "process.env.PUBLIC_PATH": env && env.PUBLIC_PATH ? JSON.stringify(env.PUBLIC_PATH) : JSON.stringify(""),
                "process.env.SCAN_EMAIL": env && env.SCAN_EMAIL ? JSON.stringify(env.SCAN_EMAIL) : JSON.stringify("<insert the lb email address >"),
                "process.env.USE_SSO": env && env.USE_SSO ? JSON.stringify(env.USE_SSO) : JSON.stringify("false")
            })
        ]
    }
}
