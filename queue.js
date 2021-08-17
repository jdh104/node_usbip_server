
'use strict';

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
}

/** @template T */
class QueueNode {
    /**
     * 
     * @param {T} val
     */
    constructor(val) {
        this.val = val;
        this.next = null;
    }
}

module.exports = { Queue };
