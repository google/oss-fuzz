// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

const Promise = require('./src/index.js').default;

module.exports.fuzz = async function(data) {
  try {
    const promise = new Promise((resolve, reject) => {
      if (data.toString() === 'reject') {
        reject(new Error('rejected'));
      } else {
        resolve(data.toString());
      }
    });

    promise.then((result) => {
      Promise.resolve('');
      result.toUpperCase();
    }, (_error) => {
    })
      .catch((_error) => {
      })
      .finally(() => {
      });

    Promise.resolve(data.toString())
      .then((result) => {
        result.toUpperCase();
      }, (_error) => {
      })
      .catch((_error) => {
      })
      .finally(() => {
      });

    Promise.reject(new Error('rejected'))
      .catch((_error) => {
      })
      .finally(() => {
      });

    const promises = [
      Promise.resolve(data.toString()),
      Promise.reject(new Error('rejected')),
      Promise.resolve(data.toString())
    ];
    Promise.all(promises)
      .then((_results) => {
        Promise.resolve('');
      }, (_error) => {
      })
      .catch((_error) => {
      })
      .finally(() => {
      });

    Promise.race(promises)
      .then((_result) => {
        Promise.resolve('');
      }, (_error) => {
      })
      .catch((_error) => {
      })
      .finally(() => {
      });

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [];
