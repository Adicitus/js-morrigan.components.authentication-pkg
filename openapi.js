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
        },
        requestBodies: {
            'morrigan.components.authentication.identitySpec': {
                description: "Specifications for a new identity in the system.",
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: [
                                'name',
                                'auth'
                            ],
                            properties: {
                                name: {
                                    description: "The username to be associated with this identity. This must be unique.",
                                    type: 'string',
                                    minLength: 1,
                                    pattern: '[A-z0-9_\-.]+'
                                },
                                functions: {
                                    description: "Privileges held by the new user.",
                                    type: 'array',
                                    items: {
                                        type: 'string',
                                        pattern: '[A-z0-9_\-.]+'
                                    }
                                },
                                auth: {
                                    description: "Authentication information: how this user should authenticate with the system.",
                                    type: 'object',
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
                                }
                            }
                        }
                    }
                },
                required: true
            },
            'morrigan.components.authentication.identityOptions': {
                description: "Options that can be set on an identity record.",
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                name: {
                                    description: "A new username to be associated with this identity. This must be unique.",
                                    type: 'string',
                                    minLength: 1,
                                    pattern: '[A-z0-9_\-.]+'
                                },
                                functions: {
                                    description: "Set of privileges to be held by this user.",
                                    type: 'array',
                                    items: {
                                        type: 'string',
                                        pattern: '[A-z0-9_\-.]+'
                                    }
                                },
                                auth: {
                                    description: "Authentication information: how this user should authenticate with the system.",
                                    type: 'object',
                                    required: [
                                        'type'
                                    ],
                                    properties: {
                                        type: {
                                            description: "Name of the authentication method to use.",
                                            type: 'string',
                                            minLength: 1,
                                            pattern: '[A-z0-9_\-.]+'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                required: true
            }
        },
        responses: {
            'morrigan.components.authentication.errorMessage.generic.403': {
                description: "No identity provided or the user is not authorized to perform the operation.",
            },
            'morrigan.components.authentication.errorMessage.generic.500': {
                desription: "Someting went wrong on the server side.",
                content: {
                    'application/json': {
                        schema: { $ref: '#/components/schemas/morrigan.components.authentication.errorMessage' }
                    }
                }
            },
            'morrigan.components.authentication.patch.success': {
                description: "Identity updated successfully.",
                content: {
                    'application/json': {
                        schema: {
                            properties: {
                                state: {
                                    description: "Status message",
                                    pattern: '^success$',
                                    type: 'string'
                                },
                                identity: {
                                    $ref: '#/components/schemas/morrigan.components.authentication.identityRecord'
                                }
                            }
                        }
                    }
                }
            },
            'morrigan.components.authentication.patch.requestError': {
                description: "Failed to update the identity, see response body for details.",
                content: {
                    'application/json': {
                        type: 'object',
                        schema: {
                            properties: {
                                state: {
                                    description: "Error status",
                                    pattern: '^request',
                                    type: 'string'
                                },
                                reason: {
                                    description: "More detailed human-readable error status message.",
                                    type: 'string'
                                }
                            }
                        }
                    }
                }
            },
            'morrigan.components.authentication.getSingle.200': {
                description: "Returns the identity record.",
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                state: {
                                    description: "Response status",
                                    type: 'string',
                                    pattern: '^success$'
                                },
                                identity: { $ref: '#/components/schemas/morrigan.components.authentication.identityRecord' }
                            }
                        }
                    }
                }
            },
            'morrigan.components.authentication.getSingle.404': {
                description: "No such identity exists.",
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                state: {
                                    description: "Error status message.",
                                    pattern: '^requestError$',
                                    type: 'string'
                                },
                                reason: {
                                    description: "More detailed human-readable error message.",
                                    pattern: '^No such identity.$',
                                    type: 'string'
                                }
                            }
                        },
                        example: { state: 'requestError', reason: 'No such identity.' }
                    }
                }
            },
            'morrigan.components.authentication.getSingle.500': {
                description: "A server error occurred.",
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                state: {
                                    description: "Error status message.",
                                    type: 'string',
                                    pattern: '^serverError$'
                                },
                                reason: {
                                    description: "More detailed human-readable error message.",
                                    type: 'string',
                                }
                            }
                        },
                        example: {state: 'serverError', reason: 'Failed to retrieve identity records.'}
                    }
                }
            }
        },
        securitySchemes: {
            authorizationToken: {
                description: "Once authenticated using an authentication provider, the returned bearer token should be included in each request to the server.",
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'jwt'
            }
        }
    },
    tags: [
        {
            name: 'Identity',
            description: "Identities form the basic principals of the system."
        },
        {
            name: 'Identity Lifecycle',
            description: "Methods used to control the creation and destruction of identities."
        }
    ],
    security: {
        authorizationToken: []
    }
}