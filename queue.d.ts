/// <reference types="node" />
/** @template T */
export class Queue<T> {
    /**
     *
     * @param {T[]} initialItems
     */
    constructor(initialItems: T[]);
    /** @type {QueueNode<T>} */
    _head: QueueNode<T>;
    /** @type {QueueNode<T>} */
    _tail: QueueNode<T>;
    count: number;
    iterate(): Generator<QueueNode<T>, void, unknown>;
    /**
     * Returns the new queue count
     * @param {T} item
     */
    enqueue(item: T): number;
    dequeue(): T | null;
    peek(): T | null;
    /**
     * @callback RemoveWherePredicate
     * @param {T} item
     * @returns {boolean}
     */
    /**
     *
     * @param {RemoveWherePredicate} predicate
     */
    removeWhere(predicate: (item: T) => boolean): T | null;
    /**
     *
     * @param {T} itemToRemove
     */
    remove(itemToRemove: T): T | null;
    [util.inspect.custom](depth: any, opts: any): string;
}
/** @template T */
declare class QueueNode<T> {
    /**
     *
     * @param {T} val
     */
    constructor(val: T);
    val: T;
    /** @type {QueueNode<T>} */
    next: QueueNode<T>;
}
import util = require("util");
export {};
