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

const { FuzzedDataProvider } = require('@jazzer.js/core')
const {
  bindActionCreators,
  createStore,
  applyMiddleware,
  combineReducers,
  compose
} = require('redux')

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data)

    const reducer1 = (state = { count: 0 }, action) => {
      switch (action.type) {
        case 'INCREMENT':
          return { ...state, count: (state.count || 0) + 1 }
        case 'DECREMENT':
          return { ...state, count: (state.count || 0) - 1 }
        case 'SET_COUNT':
          return { ...state, count: action.payload }
        default:
          return state
      }
    }

    const reducer2 = (state = { count: 0 }, action) => {
      switch (action.type) {
        case 'ADD':
          return { ...state, total: (state.total || 0) + action.payload }
        case 'SUBTRACT':
          return { ...state, total: (state.total || 0) - action.payload }
        case 'SET_TOTAL':
          return { ...state, total: action.payload }
        default:
          return state
      }
    }

    const actionCreator = () => ({
      type: 'ADD_TODO',
      payload: {
        id: provider.consumeIntegral(4, true),
        text: provider.consumeString(10),
        completed: provider.consumeBoolean()
      }
    })

    const dispatch = () => { }

    bindActionCreators(actionCreator, dispatch)

    const preloadedState = {}
    preloadedState.reducer1 = provider.consumeBoolean()
      ? { count: provider.consumeIntegral(4, true) }
      : undefined
    preloadedState.reducer2 = provider.consumeBoolean()
      ? { count: provider.consumeIntegral(4, true) }
      : undefined

    const middleware = _store => next => action => {
      if (provider.consumeBoolean()) {
        return next(action)
      } else {
        return loggerMiddleware
      }
    }

    const enhancer = provider.consumeBoolean()
      ? applyMiddleware(middleware)
      : undefined

    const store = createStore(
      combineReducers({ reducer1, reducer2 }),
      preloadedState,
      enhancer
    )

    const actionTypes = [
      'INCREMENT',
      'DECREMENT',
      'SET_COUNT',
      'ADD',
      'SUBTRACT',
      'SET_TOTAL'
    ]
    const actionType =
      actionTypes[Math.floor(Math.random() * actionTypes.length)]

    const actionPayload = provider.consumeBoolean()
      ? { payload: provider.consumeIntegral(4, true) }
      : undefined

    const action = { type: actionType, ...actionPayload }

    store.dispatch(action)

    const callback = () => { }

    store.subscribe(callback)

    const reducer3 = (state = { count: 0 }, action) => {
      switch (action.type) {
        case 'MULTIPLY':
          return { ...state, total: (state.total || 0) * action.payload }
        case 'DIVIDE':
          return { ...state, total: (state.total || 0) / action.payload }
        default:
          return state
      }
    }

    combineReducers({ reducer1, reducer2, reducer3 })

    const func1 = () => { }
    const func2 = () => { }
    const func3 = () => { }

    const funcs = [func1, func2, func3]

    compose(...funcs)
  } catch (error) {
    if (!ignoredError(error)) throw error
  }
}

function ignoredError(error) {
  return !!ignored.find(message => error.message.indexOf(message) !== -1)
}

const ignored = []

function loggerMiddleware(_store) {
  return function(next) {
    return function(action) {
      const result = next(action)
      return result
    }
  }
}

