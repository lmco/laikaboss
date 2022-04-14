
function isBuffer (obj) {
    return obj != null && obj.constructor != null &&
        typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

function keyIdentity(delimiter, key) {
    if (!isNaN(key)) {
        return '{}'
    }
    return delimiter + key
}

export default function tableFlatten(target, opts) {
    opts = opts || {}

    const delimiter = opts.delimiter || '.'
    const maxDepth = opts.maxDepth
    const transformKey = opts.transformKey || keyIdentity
    const output = []

    function step(object, prev, currentDepth) {
        currentDepth = currentDepth || 1
        Object.keys(object).forEach(function (key) {
            const value = object[key]
            const isarray = opts.safe && Array.isArray(value)
            const type = Object.prototype.toString.call(value)
            const isbuffer = isBuffer(value)
            const isobject = (
                type === '[object Object]' ||
                type === '[object Array]'
            )

            let newKey = prev
                ? prev + transformKey(delimiter, key)
                : transformKey("", key)

            if (!isarray && !isbuffer && isobject && Object.keys(value).length &&
                (!opts.maxDepth || currentDepth < maxDepth)) {
                return step(value, newKey, currentDepth + 1)
            }
            if (newKey.startsWith('{}')) {
                newKey = newKey.slice(3)
            }
            output.push({tableKey: newKey, value})
        })
    }

    step(target)

    return output
}