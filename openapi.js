module.exports = {
    components: {
        schemas: {
            'morrigan.components.authentication.identityRecord':  {
                description: "Record of an identity within the system.",
                type: 'object',
                required: [
                    '_id',
                    'name',
                    'id',
                    'authId'
                ],
                properties: {
                    _id: {
                        description: "Internal ID of this identity record.",
                        type: 'string'
                    },
                    name: {
                        description: "Username for this identity.",
                        type: 'string',
                        minLength: 1
                    },
                    id: {
                        description: "ID number of this identity within the system.",
                        type: 'string',
                        format: 'uuid',
                        readOnly: true
                    },
                    authId: {
                        description: "ID of the corresponding authentication record.",
                        type: 'string',
                        format: 'uuid',
                        readOnly: true
                    },
                    functions: {
                        description: "List of privileges that this user is granted.",
                        type: 'array',
                        items: {
                            $ref: '#/components/schemas/morrigan.components.authentication.function'
                        }
                    }
                }
            },
            'morrigan.components.authentication.function': {
                description: 'Name of a privilege that a user can hold.',
                type: 'string',
                minLength: 1,
                pattern: '^[a-zA-Z0-9](\.[a-zA-Z0-9])*$'
            },
            'morrigan.components.authentication.errorMessage': {
                description: 'Error information',
                type: 'object',
                required: [
                    'state'
                ],
                properties: {
                    state: {
                        description: "Error name",
                        type: 'string',
                        pattern: '^(request|server)[a-zA-Z0-9]+'
                    },
                    reason: {
                        description: "Human-readable string giving further error details.",
                        type: 'string'
                    }
                }
            },
            'morrigan.components.authentication.identityId': {
                description: "ID for an existing identity in the system.",
                type: 'string',
                format: 'uuid',

            }
        },
        parameters: {
            'morrigan.components.authentication.identityId': {
                name: 'identityId',
                in: 'path',
                required: true,
                description: "ID for an existing identity in the system.",
                schema: { $ref: '#/components/schemas/morrigan.components.authentication.identityId'},
                allowEmptyValue: false
            }
        }
    }
}