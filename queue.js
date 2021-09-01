
'use strict';

const util = require('util');



/** @template T */
class Queue {
    /**
     * 
     * @param {T[]} initialItems
     */
    constructor(initialItems) {
        /** @type {QueueNode<T>} */
        this._head = null;
        /** @type {QueueNode<T>} */
        this._tail = null;
        this.count = 0;

        for (let initialItem of initialItems || []) {
            this.enqueue(initialItem);
        }
    }

    [util.inspect.custom](depth, opts) {
        if (depth <= 2) {
            return 'Queue ' + util.inspect({
                count: this.count,
            });
        } else {
            return `Queue(${this.count}) ` + util.inspect([...this.iterate()].map(node => node.val), null, depth - 1);
        }
    }

    *iterate() {
        let iteratedItem = this._head;

        while (iteratedItem) {
            yield iteratedItem;
            iteratedItem = iteratedItem.next;
        }
    }

    /**
     * Returns the new queue count
     * @param {T} item
     */
    enqueue(item) {
        if (this._tail) {
            this._tail.next = new QueueNode(item);
            this._tail = this._tail.next;
        } else {
            this._head = this._tail = new QueueNode(item);
        }

        return ++this.count;
    }

    dequeue() {
        if (!this._head) {
            return null;
        } else {
            let result = this._head;

            this._head = this._head.next;
            this._tail = this._head && this._tail;

            this.count--;
            return result.val;
        }
    }

    peek() {
        if (this._head) {
            return this._head.val;
        } else {
            return null;
        }
    }

    /**
     * @callback RemoveWherePredicate
     * @param {T} item
     * @returns {boolean}
     */

    /**
     * 
     * @param {RemoveWherePredicate} predicate
     */
    removeWhere(predicate) {
        if (predicate == null) {
            throw new Error(`'predicate' cannot be ${util.inspect(predicate)} (equivalent to null)`);
        } else {
            let iterator = this.iterate();

            /** @type {QueueNode<T>} */
            let previousItem = null;
            let currentItem = previousItem;

            let iteration = iterator.next();

            do {
                previousItem = currentItem;
                currentItem = iteration.value;

                if (currentItem && predicate(currentItem.val)) {
                    let nextItem = iterator.next().value;

                    if (!previousItem) {
                        this._head = nextItem;
                    } else if (!nextItem) {
                        previousItem.next = this._tail = null;
                    } else {
                        previousItem.next = nextItem;
                    }

                    this.count--;
                    return currentItem.val;
                } else {
                    iteration = iterator.next();
                }
            } while (!iteration.done);

            return null;
        }
    }

    /**
     * 
     * @param {T} itemToRemove
     */
    remove(itemToRemove) {
        if (itemToRemove == null) {
            throw new Error(`'itemToRemove' cannot be ${util.inspect(itemToRemove)} (equivalent to null)`);
        } else {
            return this.removeWhere(item => item == itemToRemove);
        }
    }
}

/** @template T */
class QueueNode {
    /**
     * 
     * @param {T} val
     */
    constructor(val) {
        this.val = val;

        /** @type {QueueNode<T>} */
        this.next = null;
    }
}

module.exports = { Queue };
