const _ = require('lodash');

const replaceValues = (obj, find, cb) => {
    for (const [key, value] of Object.entries(obj)) {
        if (key === find) {          
            obj[key] = cb(value); 
        } else if (_.isObject(value)) {
            replaceValues(value, find, cb);
        }
    }    
};

const replace = (obj, find, cb) => {    
    let cloneObj = JSON.parse(JSON.stringify(obj));
    replaceValues(cloneObj, find, cb);
    return cloneObj;
  }

module.exports = replace;