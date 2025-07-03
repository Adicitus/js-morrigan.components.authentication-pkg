const Morrigan = require('@adicitus/morrigan.server')

let server = new Morrigan({
    stateDir: "/morrigan.server/dev/state",
    logger: {
        console: true,
        logDir: "/morrigan.server/dev/logs",
        level: 'silly'
    },
    http: {
        port: 8080,

    },
    database: {
        connectionString: "mongodb://127.0.0.1:27017",
        dbname: "morrigan-server"
    },
    components: {
        core: {
            module: '@adicitus/morrigan.components.core',

            providers: [
                '@adicitus/morrigan.server.providers.connection',
                '@adicitus/morrigan.server.providers.client',
                '@adicitus/morrigan.server.providers.capability'
            ]
        },

        auth: {
            module: require(`${__dirname}/../package`),

            providers: [
                '@adicitus/morrigan.authentication.password'
            ]
        }
    }
})

process.on('SIGINT', (e) => { server.stop(e) })
process.on('SIGTERM', (e) => { server.stop(e) })

server.setup()
server.start()