const $RefParser = require('json-schema-ref-parser');
const SwaggerParser = require('swagger-parser');
const traverse = require('traverse');
const urlJoin = require('url-join');
const _ = require('lodash');
const replace = require('./replace');
const path = require('path');
const isUrl = require('is-url');
const { resolveRefs } = require('json-refs'); // 'json-refs' resolves local references better than 'json-schema-ref-parser'

const operationTypes = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch'];

class SwaggerCombine {
  constructor(config, opts) {
    this.config = _.cloneDeep(config);
    this.opts = opts || {};
    this.apis = [];
    this.schemas = [];
    this.combinedSchema = {};
    this.cwd = process.cwd();
  }

  combine() {
    return this.load()
      .then(() => this.filterPaths())
      .then(() => this.filterParameters())
      .then(() => this.renamePaths())
      .then(() => this.renameTags())
      .then(() => this.renameDefinitions())    
      .then(() => this.renameParameters())    
      .then(() => this.excludeParameters())    
      .then(() => this.addTags())
      .then(() => this.renameOperationIds())
      .then(() => this.renameSecurityDefinitions())
      .then(() => this.dereferenceSchemaSecurity())
      .then(() => this.addSecurityToPaths())
      .then(() => this.addBasePath())
      .then(() => this.combineSchemas())
      .then(() => this.removeEmptyFields());
  }

  combineAndReturn() {
    return this.combine().then(() => this.combinedSchema);
  }

  load() {  
    return $RefParser
      .dereference(this.config, this.opts)
      .then(configSchema => {
        this.apis = configSchema.apis || [];
        this.combinedSchema = _.omit(configSchema, 'apis');

        return Promise.all(
          this.apis.map((api, idx) => {
            const opts = _.cloneDeep(this.opts);
            opts.resolve = Object.assign({}, opts.resolve, api.resolve);

            if (_.has(opts, 'resolve.http.auth.username') && _.has(opts, 'resolve.http.auth.password')) {
              const basicAuth =
                'Basic ' +
                new Buffer(`${opts.resolve.http.auth.username}:${opts.resolve.http.auth.password}`).toString('base64');
              _.set(opts, 'resolve.http.headers.authorization', basicAuth);
            }
            
            let promise;
            if (opts.noDereference) {
              // First we parse the spec from the url (local or remote)
              promise = $RefParser.parse(api.url, opts)
              if (isUrl(api.url)) {
                // TODO: Figure out how to resolve all the references from a remote url.
              } else {
                // If api.url is a local path
                // we need to resolve all the 
                // local references (if there is any)
                // inside the spec in order to get a
                // single bundled spec file. 
                promise = promise.then(res => {
                                      const options = {
                                        location: api.url,
                                        filter: 'relative',
                                        loaderOptions: {
                                          processContent: async (res, cb) => {
                                            cb(null, this.parse(res.text));
                                          },
                                        },
                                      };
                                      // This is required to jump into the 
                                      // directory where the spec is contained
                                      // so we can resolve all the relative
                                      // paths.   
                                      return resolveRefs(res, options)
                                            .then(res2 => {
                                              return res2.resolved;
                                            });
                                    });
              }
              // Once we have resolved all the local references we will
              // get rid of any remote reference by just keeping the
              // fragment (#) part of the URL. The reason why remote
              // remote references are not resolved is to force those
              // references to be added within the root swagger spec 
              // as another API spec.
              promise = promise.then(res => replace(res, "$ref", (value) => {
                                  return value.substring(value.indexOf("#"));
                                }));
            } else {
              promise = $RefParser
                          .dereference(api.url, opts)
                          .then(res => SwaggerParser.dereference(res, opts));
            }
            return promise
              .catch(err => {
                if (this.opts.continueOnError) {
                  return;
                }

                err.api = api.url;
                throw err;
              });
          })
        );
      })
      .then(apis => {
        this.schemas = apis.filter(api => !!api);
        this.apis = this.apis.filter((_api, idx) => !!apis[idx]);
        return this;
      });
  }

  filterPaths() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].paths) {
        if (this.apis[idx].paths.include && this.apis[idx].paths.include.length > 0) {
          schema.paths = _.pick(schema.paths, this.apis[idx].paths.include);
        } else if (this.apis[idx].paths.exclude && this.apis[idx].paths.exclude.length > 0) {
          schema.paths = _.omit(schema.paths, this.apis[idx].paths.exclude);
        }
      }

      return schema;
    });

    return this;
  }

  filterParameters() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].paths && this.apis[idx].paths.parameters) {
        const excludeParameters = this.apis[idx].paths.parameters.exclude;
        const includeParameters = this.apis[idx].paths.parameters.include;

        if (includeParameters && !_.isEmpty(includeParameters)) {
          _.forIn(includeParameters, (parameterToInclude, parameterPath) => {
            const hasHttpMethod = /\.(get|put|post|delete|options|head|patch)$/i.test(parameterPath);
            const pathInSchema = _.get(schema.paths, parameterPath);

            if (pathInSchema) {
              if (hasHttpMethod) {
                pathInSchema.parameters = _.filter(
                  pathInSchema.parameters,
                  curParam => curParam.name === parameterToInclude
                );
              } else {
                _.forIn(pathInSchema, (properties, method) => {
                  pathInSchema[method].parameters = _.filter(
                    pathInSchema[method].parameters,
                    curParam => curParam.name === parameterToInclude
                  );
                });
              }
            }
          });
        } else if (excludeParameters && !_.isEmpty(excludeParameters)) {
          _.forIn(excludeParameters, (parameterToExclude, parameterPath) => {
            const hasHttpMethod = /\.(get|put|post|delete|options|head|patch)$/i.test(parameterPath);
            const pathInSchema = _.get(schema.paths, parameterPath);

            if (pathInSchema) {
              if (hasHttpMethod) {
                pathInSchema.parameters = _.remove(
                  pathInSchema.parameters,
                  curParam => curParam.name !== parameterToExclude
                );
              } else {
                _.forIn(pathInSchema, (properties, method) => {
                  pathInSchema[method].parameters = _.remove(
                    pathInSchema[method].parameters,
                    curParam => curParam.name !== parameterToExclude
                  );
                });
              }
            }
          });
        }
      }

      return schema;
    });

    return this;
  }

  renameParameters() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].parameters && this.apis[idx].parameters.rename && Object.keys(this.apis[idx].parameters.rename).length > 0) {
        let renamings;

        if (_.isPlainObject(this.apis[idx].parameters.rename)) {
          renamings = [];
          _.forIn(this.apis[idx].parameters.rename, (renameParameter, parameterToRename) => {
            renamings.push({
              type: 'rename',
              from: parameterToRename,
              to: renameParameter,
            });  
          });
        } else {
          renamings = this.apis[idx].parameters.rename;
        }

        _.forEach(renamings, renaming => {
          schema.parameters = _.mapKeys(schema.parameters, (curPathValue, curPath) => this.rename(renaming, curPath));

          const rename = this.rename.bind(this);
          traverse(schema).forEach(function traverseSchema() {
            if (this.key === '$ref' && this.node === `#/parameters/${renaming.from}`) {
              this.update(`#/parameters/${renaming.to}`)
            }
          });
        });
      }

      return schema;
    });

    return this;
  }

  excludeParameters() {    
    if (this.combinedSchema.parameters) {
      const excludeParameters = Object.keys(this.combinedSchema.parameters);
      this.schemas = this.schemas.map((schema, idx) => {
        const allowGlobalOverride = (this.apis[idx].parameters && this.apis[idx].parameters.allowGlobalOverride) ? this.apis[idx].parameters.allowGlobalOverride : [];
        excludeParameters.forEach(param => {
          if (schema.parameters[param] !== undefined && allowGlobalOverride.includes(param)) {
            delete schema.parameters[param];
          }
        });
        return schema;
      });    
    }
    return this;
  }

  renameDefinitions() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].definitions && this.apis[idx].definitions.rename && Object.keys(this.apis[idx].definitions.rename).length > 0) {
        let renamings;

        if (_.isPlainObject(this.apis[idx].definitions.rename)) {
          renamings = [];
          _.forIn(this.apis[idx].definitions.rename, (renameDefinition, definitionToRename) => {
            renamings.push({
              type: 'rename',
              from: definitionToRename,
              to: renameDefinition,
            });
          });
        } else {
          renamings = this.apis[idx].definitions.rename;
        }

        _.forEach(renamings, renaming => {
          schema.definitions = _.mapKeys(schema.definitions, (curPathValue, curPath) => this.rename(renaming, curPath));

          const rename = this.rename.bind(this);
          traverse(schema).forEach(function traverseSchema() {
            if (this.key === '$ref' && this.node === `#/definitions/${renaming.from}`) {
              this.update(`#/definitions/${renaming.to}`)
            }
          });
        });
      }

      return schema;
    });

    return this;
  }
  
  renamePaths() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].paths && this.apis[idx].paths.rename && Object.keys(this.apis[idx].paths.rename).length > 0) {
        let renamings;

        if (_.isPlainObject(this.apis[idx].paths.rename)) {
          renamings = [];
          _.forIn(this.apis[idx].paths.rename, (renamePath, pathToRename) => {
            renamings.push({
              type: 'rename',
              from: pathToRename,
              to: renamePath,
            });
          });
        } else {
          renamings = this.apis[idx].paths.rename;
        }

        _.forEach(renamings, renaming => {
          schema.paths = _.mapKeys(schema.paths, (curPathValue, curPath) => this.rename(renaming, curPath));
        });
      }

      return schema;
    });

    return this;
  }

  renameOperationIds() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (
        this.apis[idx].operationIds &&
        this.apis[idx].operationIds.rename &&
        Object.keys(this.apis[idx].operationIds.rename).length > 0
      ) {
        let renamings;

        if (_.isPlainObject(this.apis[idx].operationIds.rename)) {
          renamings = [];
          _.forIn(this.apis[idx].operationIds.rename, (renameOperationId, operationIdToRename) => {
            renamings.push({
              type: 'rename',
              from: operationIdToRename,
              to: renameOperationId,
            });
          });
        } else {
          renamings = this.apis[idx].operationIds.rename;
        }

        _.forEach(renamings, renaming => {
          const rename = this.rename.bind(this);
          traverse(schema).forEach(function traverseSchema() {
            if (this.key === 'operationId') {
              const newName = rename(renaming, this.node);
              this.update(newName);
            }
          });
        });
      }

      return schema;
    });

    return this;
  }

  rename(renaming, node) {
    switch (renaming.type) {
      case 'rename':
        return this.renameByReplace(node, renaming.from, renaming.to);
      case 'regex':
      case 'regexp':
        return this.renameByRegexp(node, renaming.from, renaming.to);
      case 'fn':
      case 'fnc':
      case 'function':
        return (renaming.to || renaming.from)(node);
      default:
        return node;
    }
  }

  renameByReplace(currentValue, valueToRename, renameValue) {
    if (valueToRename === currentValue) {
      return renameValue;
    }

    return currentValue;
  }

  renameByRegexp(currentValue, valueToRename, renameValue) {
    let regex;
    if (_.isRegExp(valueToRename)) {
      regex = valueToRename;
    } else {
      regex = new RegExp(valueToRename);
    }

    return currentValue.replace(regex, renameValue);
  }

  renameTags() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].tags && this.apis[idx].tags.rename && Object.keys(this.apis[idx].tags.rename).length > 0) {
        _.forIn(this.apis[idx].tags.rename, (newTagName, tagNameToRename) => {
          traverse(schema).forEach(function traverseSchema() {
            if (this.key === 'tags' && Array.isArray(this.node) && this.node.includes(tagNameToRename)) {
              this.update(_.uniq(this.node.map(tag => (tag === tagNameToRename ? newTagName : tag))));
            }
          });
        });
      }

      return schema;
    });

    return this;
  }


  addTags() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].tags && this.apis[idx].tags.add && this.apis[idx].tags.add.length > 0) {
        this.apis[idx].tags.add.forEach(newTagName => {
          traverse(schema).forEach(function traverseSchema() {
            if (
              this.parent &&
              this.parent.parent &&
              this.parent.parent.key === 'paths' &&
              operationTypes.includes(this.key)
            ) {
              const newTags =
                this.node.tags && Array.isArray(this.node.tags)
                  ? _.uniq(this.node.tags.concat(newTagName))
                  : [newTagName];

              this.update(Object.assign({}, this.node, { tags: newTags }));
            }
          });
        });
      }

      return schema;
    });

    return this;
  }

  renameSecurityDefinitions() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (
        this.apis[idx].securityDefinitions &&
        this.apis[idx].securityDefinitions.rename &&
        Object.keys(this.apis[idx].securityDefinitions.rename).length > 0
      ) {
        _.forIn(this.apis[idx].securityDefinitions.rename, (newName, curName) => {
          if (_.has(schema.securityDefinitions, curName)) {
            // Comment this lie to fix https://github.groupondev.com/mobile/api-proxy-spec/issues/32
            // We will rename the the securityDefinitions and set one in the global combined
            //_.set(schema.securityDefinitions, newName, schema.securityDefinitions[curName]);
            _.unset(schema.securityDefinitions, curName);

            traverse(schema).forEach(function traverseSchema() {
              if (this.key === 'security' && Array.isArray(this.node) && this.node.some(sec => !!sec[curName])) {
                this.update(
                  this.node.map(sec => {
                    if (_.has(sec, curName)) {
                      _.set(sec, newName, sec[curName]);
                      _.unset(sec, curName);
                    }

                    return sec;
                  })
                );
              }
            });
          }
        });
      }

      return schema;
    });

    return this;
  }

  dereferenceSchemaSecurity() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (schema && schema.security) {
        traverse(schema).forEach(function traverseSchema() {
          if (
            /(get|put|post|delete|options|head|patch)$/i.test(this.key) &&
            this.parent &&
            this.parent.parent &&
            this.parent.parent.key === 'paths' &&
            !this.node.security
          ) {
            this.update(Object.assign({}, this.node, { security: schema.security }));
          }
        });

        _.unset(schema, 'security');
      }

      return schema;
    });

    return this;
  }

  addSecurityToPaths() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (
        this.apis[idx].paths &&
        this.apis[idx].paths.security &&
        Object.keys(this.apis[idx].paths.security).length > 0
      ) {
        _.forIn(this.apis[idx].paths.security, (securityDefinitions, pathForSecurity) => {
          const hasHttpMethod = /\.(get|put|post|delete|options|head|patch)$/i.test(pathForSecurity);
          const pathInSchema = _.get(schema.paths, pathForSecurity);

          if (pathInSchema) {
            if (hasHttpMethod) {
              _.forIn(securityDefinitions, (scope, type) => {
                pathInSchema.security = pathInSchema.security || [];
                pathInSchema.security.push({ [type]: scope });
              });
            } else {
              _.forIn(pathInSchema, (properties, method) => {
                _.forIn(securityDefinitions, (scope, type) => {
                  pathInSchema[method].security = pathInSchema[method].security || [];
                  pathInSchema[method].security.push({ [type]: scope });
                });
              });
            }
          }
        });
      }

      return schema;
    });

    return this;
  }

  addBasePath() {
    this.schemas = this.schemas.map((schema, idx) => {
      if (this.apis[idx].paths && this.apis[idx].paths.base) {
        schema.paths = _.mapKeys(schema.paths, (value, curPath) => {
          return urlJoin(this.apis[idx].paths.base, curPath);
        });
      }

      return schema;
    });

    return this;
  }

  combineSchemas() {
    const operationIds = [];

    this.schemas.forEach(schema => {
      const conflictingPaths = _.intersection(_.keys(this.combinedSchema.paths), _.keys(_.get(schema, 'paths')));
      const securityDefinitions = _.get(schema, 'securityDefinitions');
      const conflictingSecurityDefs = _.intersection(
        _.keys(this.combinedSchema.securityDefinitions),
        _.keys(securityDefinitions)
      ).filter(key => !_.isEqual(securityDefinitions[key], this.combinedSchema.securityDefinitions[key]));

      const newOperationIds = traverse(schema).reduce(function(acc, x) {
        if (
          'operationId' === this.key &&
          this.parent &&
          /(get|put|post|delete|options|head|patch)$/i.test(this.parent.key) &&
          this.parent.parent &&
          this.parent.parent.parent &&
          this.parent.parent.parent.key === 'paths'
        ) {
          acc.push(x);
        }
        return acc;
      }, []);
      const conflictingOperationIds = _.intersection(operationIds, newOperationIds);

      if (!_.isEmpty(conflictingPaths)) {
        if (this.opts.continueOnConflictingPaths) {
          for (let cPath of conflictingPaths) {
            const conflictingPathOps = _.intersection(
              _.keys(this.combinedSchema.paths[cPath]),
              _.keys(schema.paths[cPath])
            );
            if (!_.isEmpty(conflictingPathOps)) {
              throw new Error(`Name conflict in paths: ${cPath} at operation: ${conflictingPathOps.join(', ')}`);
            }
          }
        } else {
          throw new Error(`Name conflict in paths: ${conflictingPaths.join(', ')}`);
        }
      }

      if (!_.isEmpty(conflictingSecurityDefs)) {
        throw new Error(`Name conflict in security definitions: ${conflictingSecurityDefs.join(', ')}`);
      }

      if (!_.isEmpty(conflictingOperationIds)) {
        throw new Error(`OperationID conflict: ${conflictingOperationIds.join(', ')}`);
      }

      operationIds.push.apply(operationIds, newOperationIds);

      _.defaultsDeep(this.combinedSchema, _.pick(schema, ['paths', 'securityDefinitions']));

      if (this.opts.includeDefinitions) {
        this.includeTerm(schema, 'definitions');
      }

      if (this.opts.includeParameters) {
        this.includeTerm(schema, 'parameters');
      }

      if (this.opts.includeTags) {
        this.addItems(schema, 'tags');
      }

    });

    this.removeTagsNotUsed();
    this.removeTermNotUsed('definitions');
    this.removeTermNotUsed('parameters');

    return this;
  }

  includeTerm(schema, term) {
    const conflictingTerms = _.intersection(
      _.keys(this.combinedSchema[term]),
      _.keys(_.get(schema, term))
    ).filter(
      key => !_.isEqual(_.get(schema, `${term}.${key}`), _.get(this, `combinedSchema.${term}.${key}`))
    );

    if (!_.isEmpty(conflictingTerms)) {
      throw new Error(`Name conflict in ${term}: ${conflictingTerms.join(', ')}`);
    }

    _.defaultsDeep(this.combinedSchema, _.pick(schema, [term]));
  }

  

  removeTermNotUsed(term) {
    if (!this.combinedSchema[term]) {
      return
    }
    const originalScheme = this.combinedSchema;
    const newScheme = _.pickBy(this.combinedSchema, (value, key) => key !== term );
    newScheme[term] = {};

    const includeElement = (term, element, newScheme, originalScheme) => {
      if (newScheme[term][element] !== undefined || originalScheme[term][element] === undefined) {
        return;
      }
      newScheme[term][element] = originalScheme[term][element]; 
      traverse(originalScheme[term][element]).forEach(function traverseSchema() { 
        if (this.key === '$ref') {
          const name = this.node.split("/").pop(-1);
          includeElement(term, name, newScheme, originalScheme); 
        }
      });
    };
    traverse(newScheme).forEach(function traverseSchema() { 
      if (this.key === '$ref') {
        const name = this.node.split("/").pop(-1);
        includeElement(term, name, newScheme, originalScheme);
      }
    });

    // TODO fixme
    const allOfs = _.pickBy(originalScheme[term], (value, key) => value["allOf"] !== undefined );
    newScheme[term] = Object.assign(originalScheme[term], allOfs);

    this.combinedSchema = newScheme;
  }

  removeTagsNotUsed() {
    let tagsUsed = [];
    traverse(this.combinedSchema.paths).forEach(function traverseSchema() { 
      if (this.key === 'tags' && Array.isArray(this.node)) {
        tagsUsed = tagsUsed.concat(this.node)
      }
    });
    tagsUsed = _.uniq(tagsUsed);
    if (this.combinedSchema.tags) {
      this.combinedSchema.tags = this.combinedSchema.tags.filter(tag => tagsUsed.includes(tag.name));
    }
  }

  // TODO handle conflicts
  addItems(schema, term) {
    this.combinedSchema[term] = (this.combinedSchema[term] || []).concat(schema[term])
  }

  removeEmptyFields() {
    this.combinedSchema = _(this.combinedSchema)
      .omitBy(_.isNil)
      .omitBy(_.isEmpty)
      .value();
    return this;
  }

  toString(format = this.opts.format) {
    if (String(format).toLowerCase() === 'yaml' || String(format).toLowerCase() === 'yml') {
      return $RefParser.YAML.stringify(this.combinedSchema);
    }

    return JSON.stringify(this.combinedSchema, null, 2);
  }

  parse(text, format = this.opts.format) {
    if (String(format).toLowerCase() === 'yaml' || String(format).toLowerCase() === 'yml') {
      return $RefParser.YAML.parse(text);
    }
    return JSON.parse(text);
  }
}

module.exports = SwaggerCombine;
