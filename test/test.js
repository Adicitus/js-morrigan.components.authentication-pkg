const assert    = require('assert')
const fs        = require('fs')
const MongoDbServer = require('mongodb-memory-server')
const Morrigan = require('@adicitus/morrigan.server')

describe("Authentication Component", () =>  {

    var authComponent = require(`${__dirname}/../package`)

    const settings = {
        stateDir: `${__dirname}/.data/state`,
        logger: {
            console: true,
            logDir: `${__dirname}/.data/logs`,
            level: 'silly'
        },

        http: {
            port: 8080,
            secure: false
        },

        database: {
            connectionString: "mongodb://127.0.0.1:27017",
            dbname: "morrigan-authentication-test"
        },

        components: {
            auth: {
                module: authComponent,

                providers: [
                    '@adicitus/morrigan.authentication.password'
                ]
            }
        }
    }

    const http = require((settings.http.secure ? 'https' : 'http'))

    
    const call = (url, reqOpt, reqData, dataCallback) => {
        let req = http.request(url, reqOpt, res => {
            res.setEncoding('utf8')
            assert.equal(res.statusCode, 200, `Expected to receive '200 OK', but received '${res.statusCode}' using the following request options: ${JSON.stringify(reqOpt)}`)
            res.on('data', dataRaw => {
                assert.equal(typeof dataRaw, 'string', `Expected stringified JSON to be returned by the server, but found: ${ typeof dataRaw }`)
                let data = JSON.parse(dataRaw)
                assert.equal(data.state, 'success', `Expected call to succeed, but received call state ${data.state}: ${dataRaw}`)
                dataCallback(dataRaw, data)
            })
        })
        if (null !== reqData) {
            req.write(JSON.stringify(reqData))
        }
        req.end()
    }

    var mongoDbServer = null
    var morriganServer  = null
    var baseUrl = `${settings.http.secure ? 'https' : 'http'}://localhost:${settings.http.port}`
    const authBaseUrl = `${baseUrl}/api/auth`
    const idenityEndpoint = `${authBaseUrl}/identity`
    const meEndpoint = `${idenityEndpoint}/me`
            
    const testUserReqData = {
        name: 'user1',
        functions: [
            'password1'
        ],
        auth: {
            type: 'password',
            password: 'password'
        }
    }

    var adminAuthToken  = null
    var adminIdRecord   = null
    var userIdRecord    = null
    var userAuthToken   = null
    

    before(async function() {
        this.timeout(3000)
        mongoDbServer = await MongoDbServer.MongoMemoryServer.create()
        settings.database.connectionString = mongoDbServer.getUri()
        morriganServer = new Morrigan(settings)
        await morriganServer.start()
    })

    describe('REST API', () => {
        describe("Identity Lifecycle", () => {

            it("Should initialize the default 'admin' account with password 'Pa55w.rd' if there are no existing users", done => {
                
                let reqOptions = {
                    method: 'post',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
                let reqData = {
                    type: 'password',
                    name: 'admin',
                    password: 'Pa55w.rd'
                }

                call(authBaseUrl, reqOptions, reqData, (dataRaw, data) => {
                    assert(data.token, 'Expected the server to return a token, but no token included.')
                    adminAuthToken = data.token
                    done()
                })
            })

            it("GET '/identity/me' should return information about the current user identity", done =>{
                let reqOptions = {
                    method: 'get',
                    headers: {
                        'accept': 'application/json',
                        'Authorization': `Bearer ${adminAuthToken}`
                    }
                }

                call(meEndpoint, reqOptions, null, (dataRaw, data) => {
                    assert.equal(data.identity.name, 'admin', `Expected to receive identity record for 'admin', but received record for '${data.identity.name}': ${dataRaw}`)
                    adminIdRecord = data.identity
                    done()
                })
            }).timeout(3000)

            it("'admin' user should have all Identity permissions", () => {
                let dataRaw = JSON.stringify(adminIdRecord)
                assert((adminIdRecord.functions.find(f => f === 'auth.identity.create')), `Expected 'admin' user to have permission to create identities ('auth.identity.create'), but this permission is missing: ${dataRaw}`)
                assert((adminIdRecord.functions.find(f => f === 'auth.identity.get.all')), `Expected 'admin' user to have permission to read all identities ('auth.identity.get.all'), but this permission is missing: ${dataRaw}`)
                assert((adminIdRecord.functions.find(f => f === 'auth.identity.update.all')), `Expected 'admin' user to have permission to update all identities ('auth.identity.update.all'), but this permission is missing: ${dataRaw}`)
                assert((adminIdRecord.functions.find(f => f === 'auth.identity.delete.all')), `Expected 'admin' user to have permission to delete all identities ('auth.identity.delete.all'), but this permission is missing: ${dataRaw}`)
            })

            /* // TODO: Update setIdentity -> validateIdentity flow to enable name changes.
            it("PATCH '/api/auth/identity/me' should allow the current user to change name", function(done) {
                let reqOptions = {
                    method: 'patch',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${adminAuthToken}`
                    }
                }
                const newName = 'manager'
                let reqData = JSON.stringify({
                    name: newName
                })
                let req = http.request(meEndpoint, reqOptions, res => {
                    res.setEncoding('utf8')
                    res.on('data', dataRaw => {
                        let data = JSON.parse(dataRaw)
                        assert.equal(data.state, 'success', `Expected call to succeed, but received call state ${data.state}: ${dataRaw}`)
                        assert.equal(data.identity.name, newName)
                        adminIdRecord = data.identity
                        done()
                    })
                })
                req.write(reqData)
                req.end()

                done()

            }).timeout(3000)
            */

            it("Allows the creation of a new user using POST '/identity'", function(done) {
                let reqOptions = {
                    method: 'post',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${adminAuthToken}`
                    }
                }
                let reqData = testUserReqData
                call(idenityEndpoint, reqOptions, reqData, (dataRaw, data) => {
                    assert(data.identity, `Expected a key 'identity' on the returned object, but it it is missing: ${data}`)
                    userIdRecord = data.identity
                    assert(userIdRecord.name, reqData.name, `Wrong name set, expected '${reqData.name}' but found '${userIdRecord.name}.'`)
                    assert(userIdRecord.id, "Expected the system to have been assigned the new id.")
                    assert(userIdRecord.authId, "Missing authorization record ID ('authId')")
                    assert.equal(userIdRecord.functions.length, reqData.functions.length, `Unexpected number of functions listed, expected ${reqData.functions.length} but found ${userIdRecord.functions.length}.`)
                    assert.equal(userIdRecord.functions[0], reqData.functions[0], `Expected first function to be ${reqData.functions[0]} but found ${userIdRecord.functions[0]}.`)
                    done()
                })
            }).timeout(3000)

            it("Allows the new user to log in", function(done){
                let reqOptions = {
                    method: 'post',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
                let reqData = {
                    type: 'password',
                    name: testUserReqData.name,
                    password: testUserReqData.auth.password
                }
                call(authBaseUrl, reqOptions, reqData, (dataRaw, data) => {
                    assert(data.token, `Expected a key 'token' on the returned object, but it it is missing: ${dataRaw}`)
                    userAuthToken = data.token
                    done()
                })
            }).timeout(3000)

            it("PATCH '/identity/:id' should permit changing the permissions for a user identified by id", function(done){
                let reqOptions = {
                    method: 'patch',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${adminAuthToken}`
                    }
                }
                let reqData = {
                    functions: userIdRecord.functions.concat(['permission2'])
                }
                let testUserEndpoint = `${idenityEndpoint}/${userIdRecord.id}`
                
                call(testUserEndpoint, reqOptions, reqData, (dataRaw, data) =>{
                    assert(data.identity, `Expected a key 'identity' on the returned object, but it it is missing: ${dataRaw}`)
                    assert.equal(data.identity.functions.length, reqData.functions.length, `Expected updated identity to have ${reqData.functions.length} permissions, but found ${data.identity.functions.length}: ${dataRaw}`)
                    assert.equal(data.identity.functions[1], reqData.functions[1], `Expected updated identity's second permission to be ${reqData.functions[1]}, but found ${data.identity.functions[1]}: ${dataRaw}`)
                    userIdRecord = data.identity
                    done()
                })
            }).timeout(3000)

            it("PATCH '/identity/:id' should permit changing the password of the user with identified by id", function(done){
                let reqOptions = {
                    method: 'patch',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${adminAuthToken}`
                    }
                }
                let newPassword = 'password2'
                let reqData = {
                    auth: {
                        type: 'password',
                        password: newPassword
                    }
                }
                let testUserEndpoint = `${idenityEndpoint}/${userIdRecord.id}`
                call(testUserEndpoint, reqOptions, reqData, (dataRaw, data) => {
                    assert(data.identity, `Expected a key 'identity' on the returned object, but it it is missing: ${dataRaw}`)
                    assert.notEqual(userIdRecord.authId, data.identity.authId, `Expected updated identity to have a new authentication record ID, but found the old one in instead: ${data.identity.authId}`)
                    userIdRecord = data.identity
                    done()
                })
            }).timeout(10000)

            it("DELETE '/identity/:id' delete the user identified by id", function(done){
                let reqOptions = {
                    method: 'delete',
                    headers: {
                        Authorization: `Bearer ${adminAuthToken}`
                    }
                }
                let testUserEndpoint = `${idenityEndpoint}/${userIdRecord.id}`
                call(testUserEndpoint, reqOptions, null, (dataRaw, data) => {
                    done()
                })
            })
        })
    })

    describe('Component API', () => {

        const newUserDetails = {
            name: Math.random().toString(16).split('.')[1],
            auth: {
                type: 'password',
                password: Math.random().toString(16).split('.')[1]
            },
            functions: [
                'test'
            ]
        }

        var adminAuthToken  = null
        var adminIdRecord   = null
        var userIdRecord    = null
        var userAuthToken   = null

        it("Should be able to authenticate using the .authenticate method", async function() {
            let r = await authComponent.authenticate({ type: 'password', name: 'admin', password: 'Pa55w.rd' })
            assert(r, "Expected a result object to be returned by .authenticate, but nothing returned.")
            assert.equal(r.state, 'success', `Expected .authenticate call to return 'success', but received '${r.state}'`)
            assert(r.token, `Returned object expected to contain a 'token' key, but none included: ${JSON.stringify(r)}`)
            adminAuthToken = r.token
        })

        it ("Should be able to access secured endpoints using the generated token", async function() {
            let reqOptions = {
                method: 'get',
                headers: {
                    'accept': 'application/json',
                    'Authorization': `Bearer ${adminAuthToken}`
                }
            }

            let p = new Promise(resolve => {
                call(meEndpoint, reqOptions, null, (dataRaw, data) => {
                    assert.equal(data.identity.name, 'admin', `Expected to receive identity record for 'admin', but received record for '${data.identity.name}': ${dataRaw}`)
                    adminIdRecord = data.identity
                    resolve()
                })
            })

            await p
        })

        it("Should be able to add a new identity using the .addIdentity method", async function() {
            let r = await authComponent.addIdentity(newUserDetails)
            assert.equal(r.state, "success", `Expected the identity to be created, but call to .addIdentity returned '${r.state}': ${JSON.stringify(r)}`)
            assert(r.identity, `Expected returned object to contain an 'identoty' key with the details of the new identity, but key is missing: ${JSON.stringify(r)}`)
            assert.equal(r.identity.name, newUserDetails.name, `Expected the identity to be given the name '${newUserDetails.name}', but found '${r.identity.name}'`)
            assert(r.identity.authId, `Expected the new identity to have a 'authId' key with an id for user's authentication record, but key is missing: ${JSON.stringify(r.identity)}`)
            userIdRecord = r.identity
        })

        it("Should permit new identity to authenticate using the .authenticate method", async function() {
            r = await authComponent.authenticate({
                type:newUserDetails.auth.type,
                name: userIdRecord.name,
                password: newUserDetails.auth.password
            })
            assert.equal(r.state, 'success', `Expected call to .authenticate with the new identity details to be successful, but received '${r.state}': ${JSON.stringify(r)}`)
            assert(r.token, `Expected to retrieve an authorization token for new identity using .authenticate, but key 'token' is missing: ${JSON.stringify(r)}`)
            userAuthToken = r.token
        })


    })

    after(async () => {
        await morriganServer.stop('Identity Lifecycle tests finished')
        morriganServer = null
        await mongoDbServer.stop()
        mongoDbServer = null
        fs.rmSync(settings.stateDir, {recursive: true})
    })

})