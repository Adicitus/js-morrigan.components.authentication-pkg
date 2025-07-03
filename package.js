//APIAuth.js
"use strict"

const {v4: uuidv4} = require('uuid')
const TokenGenerator = require('@adicitus/jwtgenerator')

/**
 * Class containing Authentication/Authorization functionality of Morrigan.
 * 
 * This is done by managing 3 types of objects:
 *  - Identities
 *  - Authentication Records
 *  - Authentication providers
 * 
 * ##Identities##
 * An identity corresponds to a user or service that should have access to the system.
 * 
 * ##Authenticatiojn Records##
 * Each identity has an authentication record associated with it 
 *  
 */
class AuthAPI {
    name=null
    functions=null
    
    log = (msg) => { console.log(msg) }
    modulename = 'auth'
    access = {
        identity: {
            description: "Allowed to access identity functions.",

            create: {
                description: "Allowed to create new identities."
            },

            get: {
                all: {
                    description: "Allowed to read any identity."
                }
            },

            update: {
                all: {
                    description: "Allowed to update any identity."
                }
            },

            delete: {
                all: {
                    description: "Allowed to remove any identity."
                }
            }
        }
    }

    accessRights = null


    /**
     * Each authentication type should be defined by a corresponding
     * module exporting the following 3 functions:
     * 
     *   + Authenticate: Given the authentication details for an
     *     identity and login details provided by the user, this
     *     function should verify whether the login details are
     *     correct.
     * 
     *   + Validate: Given the authentication details for an identity,
     *     this function should verify that the details are correct,
     *     complete and could be used to verify login details.
     * 
     *   + Commit: Given the authentication details for an identity,
     *     should perform any tasks needed to enable verification using
     *     the  "authenticate" function.
     * 
     * 
     * Each method should return an object with a key 'state' that should contain one of:
     *   - 'success': Indicating that the operation succeeded.
     *   - 'failure': Indicating that the operation failed.
     *   - 'error': Indicating that the 
     * 
     * 
     * 
     */
     authTypes = null

     tokens = null
 
     serverId = null
     identityRecords = null
     authenticationRecords = null
     tokenRecords = null


    constructor() {
        this.name = this.modulename
        this.accessRights = this.buildAccessRightsList(this.modulename, this.access)
        this.functions = this.accessRights
    }

    /**
     * Helper function to turn the "access" object into an access right list.
     * 
     * Recursively processes all keys in the "scope" object, interpreting any key that
     * addresses an obejct with a "description" key as the name of a function to list access for.
     * 
     * 
     * 
     * @param {string} prefix 
     * @param {object} scope 
     */
    buildAccessRightsList(prefix, scope) {

        var ar_ns = Object.keys(scope)
        
        let ars = []

        for(var i in ar_ns) {
            let name = ar_ns[i]

            let fullname = `${prefix}.${name}`
            
            if (scope[name].description) {
                ars.push({ name: fullname, description: scope[name].description })
                scope[name].fullname = fullname
            }

            if (typeof scope[name] === 'object') {
                let ars_r = this.buildAccessRightsList(fullname, scope[name])
                ars = ars.concat(ars_r)
            }
        }

        return ars
    }

    /**
     * Verifies a set of identity details versus the expected format and returns a sanitized record if successful.
     * 
     * By default the only compulsory detail is 'name', since this is currently
     * used as the primary key for identityRecords.
     * 
     * 3 fields will be validated: 'name', 'auth' and 'functions'.
     * 
     * The name field should be a string matching the regex '[A-z0-9_\-.]+'.
     * 
     * The auth field will be validated by the authenticaton type provider.
     * 
     * The functions field should be an array of strings, but can be omitted altogether.
     * 
     * if calidation is successful, a sanitized record generated from the provided details
     * will be provided in the 'cleanRecord' field on the returned object.
     * 
     * Options:
     *  - newIdentity: When set to true, changes the approach. Verifies that the name IS NOT in use and requires authentication details to be specified.
     *  - validFunctions: A list of functions names to validate the function names in details against.
     * 
     * @param {object} details - Details to be verified.
     * @param {object} options - Options to modify how the functions validates the details.
     */
    async validateIdentitySpec(details, options) {

        const nameRegex     = /[A-z0-9_\-.]+/
        const functionRegex = /[A-z0-9_\-.]+/

        var cleanRecord = {}
        var authType = null

        if (!options) {
            options = {}
        }

        if (details === null || details === undefined) {
            return {state: 'requestError', reason: 'No user details provided.'}
        }

        /* ===== Start: Validate name ===== */
        if (options.newIdentity && !details.name) {
            return {state: 'requestError', reason: 'No user name specified.'}
        }

        if (details.name && !details.name.match(nameRegex)) {
            return {state: 'requestError', reason: `Invalid name format (should match regex ${nameRegex}).`}
        }

        if (details.name) {
            let i = await this.identityRecords.findOne({ name: details.name })

            if (options.newIdentity) {
                if (i) {
                    return {state: 'requestError', reason: 'Identity name already in use.'}
                }
            } else {
                if (!i) {
                    return {state: 'requestError', reason: 'No such user.'}
                }
            }
            cleanRecord.name = details.name
        }
        /* ====== End: Validate name ====== */

        
        /* ===== Start: Validate authentication ===== */
        if (options.newIdentity && !details.auth) {
            return { state: 'requestError', reason: 'No athentication details specified for new identity.' }
        }

        if (details.auth) {
            let auth = details.auth

            if (!auth.type) {
                return { state: 'requestError', reason: 'No authentication type specified.' }
            }

            authType = this.authTypes[auth.type]

            if (!authType) {
                return { state: 'serverConfigurationError', reason: `Invalid authentication type specified for user: ${auth.type}` }
            }

            if (!authType.validate) {
                return { state: 'serverConfigurationError', reason: `No validation function specified for authentication type: ${auth.type}` }
            }

            if (!authType.commit) {
                return { state: 'serverConfigurationError', reason: `No commit function specified for authentication type: ${auth.type}` }
            }

            let r = authType.validate(auth)

            if (r.state !== 'success') {
                return r
            } else {
                cleanRecord.auth = r.cleanRecord
            }
        }


        /* ====== End: Validate authentication ====== */

        if (details.functions) {
            /* ===== Start: Validate functions list ===== */
            let functions = details.functions

            if (!Array.isArray(functions)) {
                return {state: 'requestError', reason: `Functions not specified as an array.`}
            }

            let incorrectFormat = []
            for (let f in details.functions) {
                if (typeof f !== 'string' || !f.match(functionRegex)) {
                    incorrectFormat.push(f)
                }
            }

            if (incorrectFormat.length > 0) {
                return {state: 'requestError', reason: `Incorrectly formatted function names (should match regex ${functionRegex}): ${incorrectFormat.join(', ')}`}
            }

            if (options.validFunctions) {
                
                let invalidFunctions = []

                for(let f in details.functions) {
                    if (!options.validFunctions.includes(f)) {
                        invalidFunctions.push(f)
                    }
                }

                if (invalidFunctions.length > 0) {
                    return {state: 'requestError', reason: `Invalid functions named: ${invalidFunctions.join(', ')}`}
                }
            }
            cleanRecord.functions = details.functions
            /* ====== End: Validate functions list ====== */
        }

        return {state: 'success', pass: true, cleanRecord: cleanRecord, authType: authType }
    }

    /**
     * Attempts to validate a set of authentication details and returns an object
     * a new token.
     * 
     * @param {object} details - Authentication details that should be validated.
     */
    async authenticate(details) {

        let r = await this.validateIdentitySpec(details)

        if (!r.pass) {
            return r
        }

        if (!r.cleanRecord.name) {
            return { state: 'requestError', reason: 'No username specified.' }
        }

        let identity = await this.identityRecords.findOne({ name: details.name })
        let auth = await this.authenticationRecords.findOne( { id: identity.authId })

        if (!auth) {
            return { state: 'serverMissingAuthRecord', reason: 'Authentication record missing.'}
        }

        let authType = this.authTypes[auth.type]

        r = authType.authenticate(auth.commitRecord, details)
        
        if (r.state !== 'success') {
            return r
        }

        var t = await this.tokens.newToken(identity.id)
        r.token = t.token

        return r
    }

    /**
     * Adds a new identity to the authentication system.
     * 
     * The Following details should be provided:
     *  - name: The name of the identity, this is currently the primary key for identityRecords.
     *  - auth: Authentication details. This should be an object with a field called 'type'
     *      indicating which authentication method to use, along with any details required
     *      to authenticate using that method.
     *  - functions: An array of function names that the user should have access to.
     *      This can be omitted to create an identity with no rights.
     *          
     * 
     * @param {object} details - Details of the identity to add.
     */
    async addIdentity(details){

        let r = await this.validateIdentitySpec(details, { newIdentity: true })

        if (r.pass) {

            let record = r.cleanRecord
            record.id = uuidv4()

            try {
                // Register the authentication details of the identity before committing the idenitty to storage:
                r = r.authType.commit(record.auth)
                if (r.state !== 'success') {
                    return r
                }
                delete record.auth

                // Wrap the returned commitRecord before storage to avoid modifying it:
                let authRecord = {
                    id: uuidv4(),
                    type: r.commitRecord.type,
                    commitRecord: r.commitRecord
                }

                this.authenticationRecords.insertOne(authRecord)

                record.authId = authRecord.id

            } catch (e) {
                this.log(`Error occured while committing authentication details:`)
                this.log(JSON.stringify(e))
                console.log(e)
                return { state: 'serverAuthCommitFailed', reason: 'An exception occured while commiting authentication details.' }
            }

            // Make sure that the identity has a list of allowed functions:
            if (!record.functions) {
                record.functions = []
            }

            this.identityRecords.insertOne(record)
            return { state: 'success', identity: record }
        } else {
            return r
        }
    }

    /**
     * Updates an existing identity with the given details.
     * 
     * The Following details should be provided:
     *  - name: The name of the identity, this is currently the primary key for identityRecords.
     *  - auth: Authentication details. This should be an object with a field called 'type'
     *      indicating which authentication method to use, along with any details required
     *      to authenticate using that method.
     *  - functions: An array of function names that the user should have access to.
     *      This can be omitted to create an identity with no rights.
     * 
     * @param {object} details - Updated details for the identity
     */
    async setIdentity(identityId, details, options) {

        if (!options) {
            options = {}
        }

        // Step 0, validate:
        let r = await this.validateIdentitySpec(details)

        if (!r.pass) {
            return r
        }

        // Step 1, prepare update:
        var record = r.cleanRecord

        let identity = await this.identityRecords.findOne({ id: identityId })
        let newIdentity = Object.assign({}, identity)

        let newAuth = null

        let identityFields = Object.keys(identity)
        let updateFields = Object.keys(record)

        // Step 2, attempt to apply all new settigns:
        for (var ufi in updateFields) {
            let fieldName = updateFields[ufi]
            switch(fieldName) {
                case 'auth': {
                    let authType = this.authTypes[record.auth.type]
                    let r = authType.commit(record.auth)

                    if (r.state !== 'success') {
                        return { state: 'serverAuthCommitFailed', reason: 'Failed to commit the new authentication details.' }
                    }

                    newAuth = {
                        id: uuidv4(),
                        type: authType.name,
                        commitRecord: r.commitRecord
                    }
                    newIdentity.authId = newAuth.id
                    break
                }

                case 'functions': {
                    if (options.allowSecurityEdit) {
                        newIdentity[fieldName] = r.cleanRecord[fieldName]
                    }
                }

                default: {
                    if (identityFields.includes(fieldName)) {
                        newIdentity[fieldName] = r.cleanRecord[fieldName]
                    }
                }

                // Do not allow changing the ID fields.
                case 'id':  { break }
                case '_id':  { break }
            }
        }

        // Step 3, Commit changes:
        if (newAuth) {
            this.log(`Replacing authenication record ('${identity.authId}' -> '${newAuth.id}')...`)
            r = await this.authenticationRecords.replaceOne({id: identity.authId}, newAuth)
        }

        this.log(`Updating identity record '${newIdentity.id}'...`)
        r = await this.identityRecords.replaceOne({ id: identity.id}, newIdentity)

        return { state: 'success', identity: newIdentity }
    }

    /**
     * Removes an identity from the authentication store.
     * 
     * @param {string} identityId - Id of the identity to remove.
     */
    async removeIdentity(identityId){
        let r = await this.validateIdentitySpec({id: identityId})

        if (!r.pass) {
            return r
        }
        let identity = await this.identityRecords.findOne({id: identityId})
        let authId = identity.authId
        if ((this.authenticationRecords.removeOne)) {
            this.authenticationRecords.deleteOne = THIS.authenticationRecords.removeOne
        }
        await this.authenticationRecords.deleteOne({ id: authId })
        await this.identityRecords.deleteOne({id: identity.id})
        
        return { state: 'success' }
    }

    /**
     * Used to set up authentication endpoints.
     * 
     * @param {string} name Name that this file will registered as.
     * @param {object} definition Object containing the definition for this component, expected to contain a list of providers to load.
     * @param {object} router The express router to install endpoints on.
     * @param {object} serverEnv Server environment, expected to contain:
     *  + db: The database used by the server.
     *  + log: The log function to use.
     */
    async setup(name, defintion, router, serverEnv) {
        
        let providers = defintion.providers

        this.serverId = serverEnv.info.id

        this.log = serverEnv.log

        this.authTypes = await require('@adicitus/morrigan.utils.providers').setup(providers, { log: this.log, router: router })

        Object.keys(this.authTypes).forEach(type => {
            let openapi = null
            if (openapi = this.authTypes[type].openapi) {
                this.openapi.push(openapi)
            }
        })

        this.identityRecords = serverEnv.db.collection('morrigan.identities')
        this.tokenRecords = serverEnv.db.collection('morrigan.identities.tokens')
        this.authenticationRecords = serverEnv.db.collection('morrigan.authentication')

        this.tokens = new TokenGenerator({id: this.serverId, collection: this.tokenRecords, keyLifetime: { hours: 4 }})

        let identities = await this.identityRecords.find().toArray()
        let authentications = await await this.authenticationRecords.find().toArray()

        this.log(`Registered identities: ${identities.length}`)
        this.log(`Registered authentications: ${authentications.length}`)

        if (identities.length === 0) {
            this.log(`No users in DB, adding 'admin' user...`)
            let adminUser = await this.addIdentity({
                name: 'admin',
                auth: {
                    type: 'password',
                    password: 'Pa55w.rd'
                },
                functions: this.accessRights.map((ar) => { return ar.name })
            })
            
            if (adminUser.state === 'success') {
                this.log(`'admin' added with ID '${adminUser.identity.id}'`)
            } else {
                this.log(`Failed to add user 'admin':`)
                this.log(JSON.stringify(adminUser))
            }
        }

        
        /**
         * Helper function used by endpoints to ensure that the caller is authenticated and has access to the given function.
         * @param {object} req Request object
         * @param {object} res Response object
         * @param {string} functionName Name of the function to test for.
         */
        function allowAccess(req, res, functionName) {
            if (req.authenticated && req.authenticated.functions.includes(functionName)) {
                return true
            }

            res.status(403)
            res.end()
            return false
        }

        let ep_authenticate = async (req, res) => {
            
            var r = await this.authenticate(req.body)

            if (r.token) {
                res.status(200)
                res.send(JSON.stringify(r))
            } else {
                switch (r.state) {
                    case 'requestError': {
                        res.status(400)
                        break
                    }
        
                    case 'serverError': {
                        res.status(500)
                        break
                    }
        
                    case 'failed': {
                        res.status(403)
                        break
                    }
                    default: {
                        res.status(500)
                    }
                }
                res.send(JSON.stringify(r))
            }
        }

        ep_authenticate.openapi = {
            post: {
                tags: ['Authentication'],
                summary: "Authenticate with the system.",
                description: "Authenticate with the system.",
                requestBody: {
                    description: "The format of the request varies depending on the authentication type used, but the 'type' key should always be included.",
                    content: {
                        'application/json': {
                            schema: {
                                required: [
                                    'type'
                                ],
                                properties: {
                                    type: {
                                        description: "The type of authentication to use. This is should correspond to the name of a loaded authentication provider.",
                                        type: 'string',
                                        minLength: 1,
                                        pattern: '[A-z0-9_\-.]+'
                                    }
                                }
                            },
                            example: {
                                type: 'password',
                                name: 'user',
                                password: 'password'
                            }
                        }
                    }
                },
                responses: {
                    200: {
                        description: "Successfully authenticated, find the token in the 'token' key of the returned object.",
                        content: {
                            'application/json': {
                                schema: {
                                    properties: {
                                        state: {
                                            description: "Status message.",
                                            type: 'string',
                                            pattern: '^success$'
                                        },
                                        token: {
                                            type: 'string',
                                            format: 'jwt',
                                            pattern: '^[a-zA-Z0-9\/+]+\.[a-zA-Z0-9\/+]+\.[a-zA-Z0-9\/+]+$'
                                        }
                                    }
                                },
                                example: {
                                    "state":  "success",
                                    "token":  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjQ1ZWFlNjNiLTYzNmYtNDcwNC04ZDk4LTYyMzIyZjMwMDJiNCJ9.eyJzdWIiOiIyYmY0NTA5Zi1jYjRkLTRlNTctOGI0MC1hMzVlZWJlM2Q1MGQiLCJpc3MiOiI5ZWJiNjM5Yy0zODFjLTRmOTctYjlhZS0zYWQxOTgwNzFiMjAiLCJpYXQiOjE2NTk2OTI3OTUsImV4cCI6MTY1OTY5NDU5NX0.AAAAAEoTJuoOC1wHIvkNt-kGFrIiXSOctMEDaGdHUtEAAAAAS5G2aRmWgirN3RezVCa6dHV7O9ck3jhPKpZ8mA"
                                }
                            }
                        }
                    },
                    400: {
                        description: "Failed to authenticate, invalid request. See response body for details.",
                        content: {
                            'application/json': {
                                schema: {
                                    $ref: '#/components/schemas/morrigan.components.authentication.errorMessage'
                                },
                                examples: {
                                    'No username specified': { value: { state: 'requestError', reason: 'No username specified.' } },
                                    'Invalid username format': { value: {state: 'requestError', reason: `Invalid name format (should match regex /[A-z0-9_\-.]+/).`} },
                                    'Username taken': { value: {state: 'requestError', reason: 'Identity name already in use.'} },
                                    'No auth details specified': { value: { state: 'requestError', reason: 'No athentication details specified for new identity.' } },
                                    'No auth type specified': { value: { state: 'requestError', reason: 'No authentication type specified.' } }
                                }
                            }
                        }
                    },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    500: {
                        description: "Authentication failed due to an error on the server side.",
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/morrigan.components.authentication.errorMessage' },
                                examples: {
                                    'Missing auth record': { value: { state: 'serverMissingAuthRecord', reason: 'Authentication record missing.' } },
                                    'Invalid auth type': { value: { state: 'serverConfigurationError', reason: `Invalid authentication type specified for user: ${auth.type}` } },
                                    'No validation function': { value: { state: 'serverConfigurationError', reason: `No validation function specified for authentication type: ${auth.type}` } },
                                    'No commit function': { value: { state: 'serverConfigurationError', reason: `No commit function specified for authentication type: ${auth.type}` } }
                                }
                            }
                        }
                    }
                },
                security: {}
            }
        }

        /**
         * Authentication endpoint.
         */
        router.post('/', ep_authenticate)

        /**
         * Middleware to protect identity functions.
         */
        router.use(`/identity`, (req, res, next) => {

            if (!req.authenticated) {
                res.status(403)
                res.end()
                return
            }

            next()
        })

        let ep_newIdentity = async (req, res) => {
            
            if (!allowAccess(req, res, this.access.identity.create.fullname)) { return }

            if (!req.body) {
                res.status(400)
                res.end(JSON.stringify({status: 'requestError', reason: 'No user details provided.'}))
                return
            }

            let details = req.body

            let r = await this.addIdentity(details)

            if (r.state === 'success') {
                res.status(200)
                res.send(JSON.stringify(r))
                return
            }

            if (r.state.match(/^request/)) {
                res.status(400)
            } else {
                res.status(500)
            }
            
            res.send(JSON.stringify(r))
        }

        ep_newIdentity.openapi = {
            post : {
                tags: ['Identity', 'Identity Lifecycle'],
                description: "Create a new identity in the system.",
                summary: "Create a new identity",
                requestBody: { $ref: '#/components/requestBodies/morrigan.components.authentication.identitySpec' },
                responses: {
                    200: {
                        description: "The new identity was added.",
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        state: {
                                            description: "Operation status message.",
                                            type: 'string',
                                            pattern: '^success$'
                                        },
                                        identity: { $ref: '#/components/schemas/morrigan.components.authentication.identityRecord' }
                                    }
                                }
                            }
                        }
                    },
                    400: {
                        description: "Failed to add the identity due to issues with the request body informstion.",
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        state: {
                                            description: "Error status message.",
                                            type: 'string',
                                            pattern: '^request'
                                        },
                                        reason: {
                                            description: "More detailed human-readable description of the error."
                                        }
                                    }
                                },
                                examples: {
                                    'Missing authentication details provided': {
                                        value: { state: 'requestError', reason: 'No athentication details specified for new identity.' }
                                    },
                                    'Missing authentication type': {
                                        value: { state: 'requestError', reason: 'No authentication type specified.' }
                                    }
                                }
                            }
                        }
                    },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    500: {
                        description: "Failed to add the identity due to an issue on the server.",
                        content: {
                            'application/json': {
                                schema: {
                                    $ref: '#/components/schemas/morrigan.components.authentication.errorMessage'
                                },
                                examples: {
                                    'Invalid authentication type': {
                                        value: { state: 'serverConfigurationError', reason: `Invalid authentication type specified for user: myAuthProvider` }
                                    },
                                    'No validation function specified': {
                                        value: { state: 'serverConfigurationError', reason: `No validation function specified for authentication type: myAuthProvider` }
                                    },
                                    'No commit function specified': {
                                        value: { state: 'serverConfigurationError', reason: `No commit function specified for authentication type: myAuthProvider` }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        /**
         * Add identity endpoint.
         */
        router.post(`/identity`, ep_newIdentity)

        let ep_getIdentities = (req, res) => {
            if (!allowAccess(req, res, this.access.identity.get.all.fullname)) { return }

            this.identityRecords.find().toArray().then(o => {
                res.status(200)
                res.send(JSON.stringify({state: 'success', identities: o}))
            }).catch(e => {
                this.log(JSON.stringify(e))
                res.status(500)
                res.send(JSON.stringify({state: 'serverError', reason: 'Failed to retrieve identity records.'}))
            })
        }

        ep_getIdentities.openapi = {
            get: {
                tags: ['Identity'],
                description: "Retrieves all identity records in the the system.",
                summary: "Retrieve all identities.",
                responses: {
                    200: {
                        description: "Returns an array of all identity records in the system.",
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'array',
                                    items: { $ref: '#/components/schemas/morrigan.components.authentication.identityRecord' }
                                }
                            }
                        }
                    },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    500: {
                        description: "Someting went wrong on the server side.",
                        content: {
                            'application/json': {
                                type: 'object',
                                schema: {
                                    $ref: '#/components/schemas/morrigan.components.authentication.errorMessage'
                                },
                                example: { state: 'serverError', reason: 'Failed to retrieve identity records.' }
                                
                            }
                        }
                    }
                }
            }
        }

        /**
         * Get identityRecords endpoint
         */
        router.get(`/identity`, ep_getIdentities)

        let ep_getIdentityMe = (req, res) => {
            this.log('Entered ep_getIdentityMe', 'debug')
            this.identityRecords.find({id: req.authenticated.id}).toArray().then(o => {
                if (o.length === 0) {
                    res.status(404)
                    res.send(JSON.stringify({state: 'requestError', reason: 'No such identity.'}))
                    return
                }

                res.status(200)
                res.send(JSON.stringify({state: 'success', identity: o[0]}))
            }).catch(e => {
                this.log(JSON.stringify(e))
                res.status(500)
                res.send(JSON.stringify({state: 'serverError', reason: 'Failed to retrieve identity records.'}))
            })
        }

        ep_getIdentityMe.openapi = {
            get: {
                tags: ['Identity'],
                description: "Retrieves the identity record for the calling identity.",
                summary: "Retrieves identity for the caller.",
                responses: {
                    200: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.200' },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    404: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.404' },
                    500: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.500' }
                }
            }
        }

        /**
         * Get my identityRecord endpoint
         */
        router.get(`/identity/me`, ep_getIdentityMe)

        let ep_getIdentityById = (req, res) => {
            if (!allowAccess(req, res, this.access.identity.get.all.fullname)) { return }

            this.identityRecords.find({ id: req.params.identityId }).toArray().then(o => {
                if (o.length === 0) {
                    res.status(404)
                    res.send(JSON.stringify({state: 'requestError', reason: 'No such identity.'}))
                    return
                }

                res.status(200)
                res.send(JSON.stringify({state: 'success', identity: o[0]}))
            }).catch(e => {
                this.log(JSON.stringify(e))
                res.status(500)
                res.send(JSON.stringify({state: 'serverError', reason: 'Failed to retrieve identity records.'}))
            })
        }

        ep_getIdentityById.openapi = {
            get: {
                tags: ['Identity'],
                description: "Retrieves the identity record for the specified identity ID.",
                summary: "Retrieves identity by ID.",
                parameters: [
                    { $ref: '#/components/parameters/morrigan.components.authentication.identityId' }
                ],
                responses: {
                    200: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.200' },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    404: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.404' },
                    500: { $ref: '#/components/responses/morrigan.components.authentication.getSingle.500' }
                }
            }
        }

        /**
         * Get specific identityRecord endpoint
         */
        router.get(`/identity/:identityId`, ep_getIdentityById)



        let ep_patchIdentityMe = async (req, res) => {

            if (!req.body) {
                res.status(400)
                res.send(JSON.stringify({status: 'requestError', reason: 'No user details provided.'}))
                return
            }

            if (req.body.functions) {
                res.status(403)
                res.send(JSON.stringify({status: 'requestError', reason: 'Access to functions cannot be modified via the "me" endpoint.'}))
                return
            }

            let r = await this.setIdentity(req.authenticated.id, req.body)

            if (r.state === 'success') {
                res.status(200)
                res.send(JSON.stringify(r))
                return
            }

            if (r.state.match(/^request/)) {
                res.status(400)
            } else {
                res.status(500)
            }
            
            res.send(JSON.stringify(r))
        }

        ep_patchIdentityMe.openapi = {
            patch: {
                tags: ['Identity'],
                description: "Updates the identity of the caller.",
                summary: "Update the identity of the caller.",
                requestBody: { $ref: '#/components/requestBodies/morrigan.components.authentication.identityOptions' },
                responses: {
                    200: { $ref: '#/components/responses/morrigan.components.authentication.patch.success' },
                    400: { $ref: '#/components/responses/morrigan.components.authentication.patch.requestError' },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    500: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.500' }
                }
            }
        }

        /**
         * Update identity endpoint.
         */
        router.patch(`/identity/me`, ep_patchIdentityMe)

        let ep_patchIdentity = async (req, res) => {
            if (!allowAccess(req, res, this.access.identity.update.all.fullname)) { return }

            if (!req.body) {
                res.status(400)
                res.send(JSON.stringify({status: 'requestError', reason: 'No user details provided.'}))
                return
            }

            let r = await this.setIdentity(req.params.identityId, req.body, { allowSecurityEdit: true })

            if (r.state === 'success') {
                res.status(200)
                res.send(JSON.stringify(r))
                return
            }

            if (r.state.match(/^request/)) {
                res.status(400)
            } else {
                res.status(500)
            }
            
            res.send(JSON.stringify(r))
        }

        ep_patchIdentity.openapi = {
            patch: {
                tags: ['Identity'],
                description: "Updates an identity in the system.",
                summary: "Updates an identity in the system.",
                requestBody: { $ref: '#/components/requestBodies/morrigan.components.authentication.identityOptions' },
                parameters: [
                    { $ref: '#/components/parameters/morrigan.components.authentication.identityId' }
                ],
                responses: {
                    200: { $ref: '#/components/responses/morrigan.components.authentication.patch.success' },
                    400: { $ref: '#/components/responses/morrigan.components.authentication.patch.requestError' },
                    403: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403' },
                    500: { $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.500' }
                }
            }
        }

        /**
         * Update identity endpoint.
         */
        router.patch(`/identity/:identityId`, ep_patchIdentity)



        let ep_delete = async (req, res) => {
            if (!allowAccess(req, res, this.access.identity.delete.all.fullname)) { return }

            let r = await this.removeIdentity(req.params.identityId)

            if (r.state === 'success') {
                res.status(200)
            } else {
                if (/^request/.test(r.state)) {
                    res.status(404)
                } else {
                    res.status(500)
                }
            }

            res.send(JSON.stringify(r))
        }

        ep_delete.openapi = {
            delete: {
                tags: ['Identity', 'Identity Lifecycle'],
                description: "Removes the specified user from the system.",
                summary: "Removes the specified user from the system.",
                parameters: [
                    { $ref: '#/components/parameters/morrigan.components.authentication.identityId' }
                ],
                responses: {
                    200: {
                        description: "The identity was removed.",
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        state: {
                                            type: 'string',
                                            pattern: '^success$'
                                        }
                                    }
                                },
                                example: {
                                    state: 'success'
                                }
                            }
                        }
                    },
                    403: {
                        $ref: '#/components/responses/morrigan.components.authentication.errorMessage.generic.403'
                    },
                    404: {
                        description: "Failed to remove the identity because it does not exist.",
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/morrigan.components.authentication.errorMessage' },
                                example: {
                                    state: 'requestError', reason: 'No such user.'
                                }
                            }
                        }
                    },
                    500: {
                        desription: "Someting went wrong on the server side.",
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/morrigan.components.authentication.errorMessage' }
                            }
                        }
                    }
                }
            }
        }

        /**
         * Remove identity endpoint
         */
        router.delete(`/identity/:identityId`, ep_delete)
    }

    /**
     * Hook to be triggered when the systems shuts down.
     */
    async onShutdown() {
        this.tokens.dispose()
    }

    /**
     * Returns a middleware function that can be used to verify the authentication status of incoming requests.
     * 
     * The middleware will attempt to validate the token in the "Authorization" header, and sets req.authenticated
     * with user details if authorization is validated.
     * 
     * @returns The verification middleware.
     */
    getMiddleware() {
        /**
         * Define self here to create a refernce to this object, which makes it available
         * in the returned closure (as 'this' will be different).
         */
        let self = this
        return async (req, res, next) => {

            try {
                var auth = req.headers.authorization

                if (auth) {
                    var m = auth.match(/^(?<type>bearer) (?<token>.+)/i)
                    if (m) {
                        let r  = await self.tokens.verifyToken(m.groups.token)
                        if (r.success) {
                            var identity = await self.identityRecords.findOne({id: r.subject})
        
                            if (identity) {
                                req.authenticated = identity
                            }
                        } else {
                            self.log(`Authorization failed for ${req.method} request to secured endpoint '${req.path}' from ${req.socket.remoteAddress}:${req.socket.remotePort} on ${req.socket.localAddress}:${req.socket.localPort}`, 'error')
                            self.log(`Token: ${m.groups.token}`, 'debug')
                        }
                    }
                } else {
                    self.log(`Received ${req.method} request to secured endpoint '${req.path}' without Authorization header from ${req.socket.remoteAddress}:${req.socket.remotePort} on ${req.socket.localAddress}:${req.socket.localPort}`)
                } 
            }catch(e) {
                self.log(`Unexpected fatal error in authenitcation middleware.`, 'debug')
                self.log(JSON.stringify(e), 'error')
            }
                
            next()
        }
    }
}

const auth = new AuthAPI()
auth.openapi = []
auth.openapi.push(require(`${__dirname}/openapi`))

module.exports = auth