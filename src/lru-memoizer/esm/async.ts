import cloneDeep from 'lodash.clonedeep'
import { LRUCache } from 'lru-cache'
import events from 'node:events'
import { deepFreeze } from './freeze.js'
import { syncMemoizer } from './sync.js'
import {
  INodeStyleCallBack as CB,
  IParamsBase0,
  IParamsBase1,
  IParamsBase2,
  IParamsBase3,
  IParamsBase4,
  IParamsBase5,
  IParamsBase6,
  IParamsBasePlus,
  ResultBase
} from './util.js'

type Callback = (err?: unknown, ...args: unknown[]) => void

type PendingLoad = {
  queue: Callback[]
  expiresAt: number
}

export interface IMemoized<T1, T2, T3, T4, T5, T6, TResult> extends ResultBase {
  (cb: CB<TResult>): void
  (a1: T1, cb: CB<TResult>): void
  (a1: T1, a2: T2, cb: CB<TResult>): void
  (a1: T1, a2: T2, a3: T3, cb: CB<TResult>): void
  (a1: T1, a2: T2, a3: T3, a4: T4, cb: CB<TResult>): void
  (a1: T1, a2: T2, a3: T3, a4: T4, a5: T5, cb: CB<TResult>): void
  (a1: T1, a2: T2, a3: T3, a4: T4, a5: T5, a6: T6, cb: CB<TResult>): void
}

interface IMemoizableFunction0<TResult> {
  (cb: CB<TResult>): void
}
interface IMemoizableFunction1<T1, TResult> {
  (a1: T1, cb: CB<TResult>): void
}
interface IMemoizableFunction2<T1, T2, TResult> {
  (a1: T1, a2: T2, cb: CB<TResult>): void
}
interface IMemoizableFunction3<T1, T2, T3, TResult> {
  (a1: T1, a2: T2, a3: T3, cb: CB<TResult>): void
}
interface IMemoizableFunction4<T1, T2, T3, T4, TResult> {
  (a1: T1, a2: T2, a3: T3, a4: T4, cb: CB<TResult>): void
}
interface IMemoizableFunction5<T1, T2, T3, T4, T5, TResult> {
  (a1: T1, a2: T2, a3: T3, a4: T4, a5: T5, cb: CB<TResult>): void
}
interface IMemoizableFunction6<T1, T2, T3, T4, T5, T6, TResult> {
  (a1: T1, a2: T2, a3: T3, a4: T4, a5: T5, a6: T6, cb: CB<TResult>): void
}
interface IMemoizableFunctionPlus {
  (...rest: unknown[]): void
}

interface AsyncParamsPlus extends IParamsBasePlus {
  load: IMemoizableFunctionPlus
}
interface AsyncParams0<TResult> extends IParamsBase0<TResult> {
  load: IMemoizableFunction0<TResult>
}
interface AsyncParams1<T1, TResult> extends IParamsBase1<T1, TResult> {
  load: IMemoizableFunction1<T1, TResult>
}
interface AsyncParams2<T1, T2, TResult> extends IParamsBase2<T1, T2, TResult> {
  load: IMemoizableFunction2<T1, T2, TResult>
}
interface AsyncParams3<T1, T2, T3, TResult>
  extends IParamsBase3<T1, T2, T3, TResult> {
  load: IMemoizableFunction3<T1, T2, T3, TResult>
}
interface AsyncParams4<T1, T2, T3, T4, TResult>
  extends IParamsBase4<T1, T2, T3, T4, TResult> {
  load: IMemoizableFunction4<T1, T2, T3, T4, TResult>
}
interface AsyncParams5<T1, T2, T3, T4, T5, TResult>
  extends IParamsBase5<T1, T2, T3, T4, T5, TResult> {
  load: IMemoizableFunction5<T1, T2, T3, T4, T5, TResult>
}
interface AsyncParams6<T1, T2, T3, T4, T5, T6, TResult>
  extends IParamsBase6<T1, T2, T3, T4, T5, T6, TResult> {
  /**
   * The function that loads the resource when is not in the cache.
   */
  load: IMemoizableFunction6<T1, T2, T3, T4, T5, T6, TResult>
}

// @ts-expect-error WARNING: unknown type
function asyncMemoizer<TResult>(
  options: AsyncParams0<TResult>
): IMemoized<unknown, unknown, unknown, unknown, unknown, unknown, TResult>
function asyncMemoizer<T1, TResult>(
  options: AsyncParams1<T1, TResult>
): IMemoized<T1, unknown, unknown, unknown, unknown, unknown, TResult>
function asyncMemoizer<T1, T2, TResult>(
  options: AsyncParams2<T1, T2, TResult>
): IMemoized<T1, T2, unknown, unknown, unknown, unknown, TResult>
function asyncMemoizer<T1, T2, T3, TResult>(
  options: AsyncParams3<T1, T2, T3, TResult>
): IMemoized<T1, T2, T3, unknown, unknown, unknown, TResult>
function asyncMemoizer<T1, T2, T3, T4, TResult>(
  options: AsyncParams4<T1, T2, T3, T4, TResult>
): IMemoized<T1, T2, T3, T4, unknown, unknown, TResult>
function asyncMemoizer<T1, T2, T3, T4, T5, TResult>(
  options: AsyncParams5<T1, T2, T3, T4, T5, TResult>
): IMemoized<T1, T2, T3, T4, T5, unknown, TResult>
function asyncMemoizer<T1, T2, T3, T4, T5, T6, TResult>(
  options: AsyncParams6<T1, T2, T3, T4, T5, T6, TResult>
): IMemoized<T1, T2, T3, T4, T5, T6, TResult>
function asyncMemoizer<T1, T2, T3, T4, T5, T6, TResult>(
  options: AsyncParamsPlus
): IMemoized<T1, T2, T3, T4, T5, T6, TResult> {
  // @ts-expect-error WARNING: unknown type
  const cache = new LRUCache(options)
  const load = options.load
  const hash = options.hash
  const bypass = options.bypass
  const itemMaxAge = options.itemMaxAge
  const freeze = options.freeze
  const clone = options.clone
  const queueMaxAge = options.queueMaxAge || 1000
  const loading = new Map<string, PendingLoad>()
  const emitter = new events.EventEmitter()

  const memoizerMethods = Object.assign(
    {
      del,
      // @ts-expect-error WARNING: unknown type
      reset: () => cache.reset(),
      keys: cache.keys.bind(cache),
      on: emitter.on.bind(emitter),
      once: emitter.once.bind(emitter)
    },
    options
  )

  if (options.disable) {
    return Object.assign(load, memoizerMethods) as IMemoized<
      T1,
      T2,
      T3,
      T4,
      T5,
      T6,
      TResult
    >
  }

  function del(...args: Callback[]) {
    const key = hash(...args)
    // @ts-expect-error WARNING: unknown type
    cache.del(key)
  }

  function add(key: string, parameters: unknown[], result: unknown[]) {
    if (freeze) {
      result.forEach(deepFreeze)
    }

    if (itemMaxAge) {
      // @ts-expect-error WARNING: unknown type
      cache.set(key, result, itemMaxAge(...parameters.concat(result)))
    } else {
      cache.set(key, result)
    }
  }

  function runCallbacks(callbacks: Callback[], args: unknown[]) {
    for (const callback of callbacks) {
      // Simulate async call when returning from cache
      // and yield between callback resolution
      if (clone) {
        setImmediate(callback, ...args.map(cloneDeep))
      } else {
        setImmediate(callback, ...args)
      }
    }
  }

  function emit(event: string, ...parameters: unknown[]) {
    emitter.emit(event, ...parameters)
  }

  function memoizedFunction(...args: Callback[]) {
    const parameters = args.slice(0, -1)
    const callback: Callback = args.slice(-1).pop() as Callback
    let key: string

    if (bypass && bypass(...parameters)) {
      emit('miss', ...parameters)
      return load(...args)
    }

    if (parameters.length === 0 && !hash) {
      //the load function only receives callback.
      key = '_'
    } else {
      key = hash(...parameters)
    }

    const fromCache = cache.get(key)
    if (fromCache) {
      emit('hit', ...parameters)
      // found, invoke callback
      return runCallbacks(
        [callback],
        [null].concat(fromCache as ConcatArray<null>)
      )
    }

    const pendingLoad = loading.get(key)
    if (pendingLoad && pendingLoad.expiresAt > Date.now()) {
      // request already in progress, queue and return
      pendingLoad.queue.push(callback)
      emit('queue', ...parameters)
      return
    }

    emit('miss', ...parameters)

    const started = Date.now()

    // no pending request or not resolved before expiration
    // create a new queue and invoke load
    const queue = [callback]
    loading.set(key, {
      queue,
      expiresAt: started + queueMaxAge
    })

    const loadHandler = (...args: unknown[]) => {
      const err = args[0]
      if (!err) {
        add(key, parameters, args.slice(1))
      }

      // this can potentially delete a different queue than `queue` if
      // this callback was called after expiration.
      // that will only cause a new call to be performed and a new queue to be
      // created
      loading.delete(key)

      emit('loaded', Date.now() - started, ...parameters)
      runCallbacks(queue, args)
    }

    load(...parameters, loadHandler)
  }

  return Object.assign(memoizedFunction, memoizerMethods) as IMemoized<
    T1,
    T2,
    T3,
    T4,
    T5,
    T6,
    TResult
  >
}

asyncMemoizer.sync = syncMemoizer

export { asyncMemoizer }
