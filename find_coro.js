function log(x) {
    host.diagnostics.debugLog(x + "\n")
}

function exec(cmdstr) {
    return host.namespace.Debugger.Utility.Control.ExecuteCommand(cmdstr);
}

function find_all_coro_frames(coro_fn_addres, limit) {
    var lines = exec("!mex.fel -x \"dq 0x${@#Line}+0x40 L1\"  !mex.head -n " + limit + " !mex.cut -f 5 !mex.grep busy !ext.heap -srch " + coro_fn_addres);
    var parent_coro_frames = [];
    for (line of lines) {
        var splits = line.split(" ");
        var parent_coro_address = splits[0].replace('`','');
        var parent_fn_address = splits[2].replace('`','');

        if (parent_fn_address !== coro_fn_addres) {
            continue;
        }

        // log(parent_fn_address + " == " + coro_fn_addres);
        parent_coro_frames.push({co_address: parseInt(parent_coro_address, 16), fn_address: parent_fn_address});
    }

    return parent_coro_frames;
}

function is_valid_address(address) {
    return address > 0x100000; // todo: should be some high value;
}

function walk_parent_chain(child, depth) {
    if (depth <= 0) {
        return [];
    }

    var co_address = child.co_address;
    var heap_adress = co_address - 0x40;
    var parent_co_ref_addres = heap_adress + 0x10;

    if (!is_valid_address(parent_co_ref_addres)) {
        return [];
    }

    try
    {
        // log("parent_co_ref_addres.toString(16): 0x" + parent_co_ref_addres.toString(16));
        try
        {
            var parent_coro_address_str = host.memory.readMemoryValues(parent_co_ref_addres, 1, 8);
        }
        catch(ex)
        {
            // log("first: "+ ex);
            return [];
        }

        var parent_coro_address = parseInt(parent_coro_address_str, 16);
        var parent_fn_address = host.memory.readMemoryValues(parent_coro_address, 1, 8);

        // log("  > " + parent_coro_address_str + " " + parent_fn_address);
        var stack = walk_parent_chain({co_address: parent_coro_address, fn_address: parent_fn_address}, depth - 1);
        stack.push(child);
        return stack;
    }
    catch (ex)
    {
        // log("second: " + ex);
    }

    return [child];
}

function find_coroutines(coro_fn_addres, limit, depth) {
    var parents = find_all_coro_frames(coro_fn_addres, limit);
    var fn_stacks = new Map();
    for (let i = 0; i < parents.length; ++i) {
        var parent  = parents[i];
        log("> " + parent.co_address + " " + parent.fn_address);
        var stack = walk_parent_chain(parent, depth);
        var fn_stack = stack.reduce(function(acc, s) { return acc + "," + s.fn_address; }, "");

        if (fn_stacks.has(fn_stack)) {
            fn_stacks.set(fn_stack, fn_stacks.get(fn_stack) + 1);
        } else {
            fn_stacks.set(fn_stack, 1);
        }
    }

    log("size: " + fn_stacks.size);
    for (const [key, value] of fn_stacks) {
        log(key + " => " + value);
    }
}