// Groups all coroutine frames for a coroutine function.
// This is a best effort system. This will not give right answers as walking up the coroutine parent frames we don't know when to stop.
// parameters:
// coro_fn_address  : (String) Address of coroutine function for which you want to find all stack frames.
//                    You can get this value from output of `x FabricRuntime!*TStore*TryGetValueAsync*_ResumeCoro$2`.
// first_n          : (Int) Look at first n heaps containing coro_fn_address.
// call_stack_depth : (Int) Depth to go down in call stack. Start from low numbers like `3`.
// dll_base_start   : (Long) start address of functions above which only we consider coroutine walk to continue.
// dll_base_end     : (Long) end address of functions under which we consider coroutine walk to continue.
//                    You can get dll_base_start/end from e.g. `lmDf m FabricRuntime`
// example usage:
//> dx @$scriptContents.unique_coroutine_frames("00007ff62318bf80", 600, 3, 0x00007ff621310000, 0x00007ff624210000)
// Printing Map.
// Map size: 1
//,0x7ff62210b9f0,0x7ff623035ee0,00007ff62318bf80 => 512
//> u 00007ff62318bf80
//  Fabric!Data::TStore::Store<KSharedPtr<KString>,KSharedPtr<KBuffer> >::TryGetValueAsync$_ResumeCoro$2 [C:\__w\1\s\src\prod\src\data\tstore\Store.h @ 1040]:
//> u 0x7ff623035ee0
//  Fabric!Data::TStore::Store<KSharedPtr<KString>,KSharedPtr<KBuffer> >::ConditionalGetAsync$_ResumeCoro$2 [C:\__w\1\s\src\prod\src\data\tstore\Store.h @ 846]:
//> u 0x7ff62210b9f0
//  Fabric!<lambda_82983005e362cd54ae843770683bcb01>$_ResumeCoro$2::operator() [C:\__w\1\s\src\prod\src\Store\TSReplicatedStore.cpp @ 540]:
function unique_coroutine_frames(coro_fn_addres, first_n, call_stack_depth, dll_base_start, dll_base_end) {
    dll_base_start = parseInt(dll_base_start, 16);
    dll_base_end = parseInt(dll_base_end, 16);

    var parents = find_all_coro_frames(coro_fn_addres, first_n);
    var fn_stacks = new Map();
    for (let i = 0; i < parents.length; ++i) {
        var parent  = parents[i];
        // log("> " + parent.co_address + " " + parent.fn_address);
        var stack = walk_parent_chain(parent, call_stack_depth, dll_base_start, dll_base_end);
        var fn_stack = stack.reduce(function(acc, s) { return acc + "," + s.fn_address; }, "");

        if (fn_stacks.has(fn_stack)) {
            fn_stacks.set(fn_stack, fn_stacks.get(fn_stack) + 1);
        } else {
            fn_stacks.set(fn_stack, 1);
        }
    }

    log("Printing Map.\nMap size: " + fn_stacks.size);
    for (const [key, value] of fn_stacks) {
        log(key + " => " + value);
    }

    return fn_stacks;
}

function log(x) {
    host.diagnostics.debugLog(x + "\n")
}

function exec(cmdstr) {
    return host.namespace.Debugger.Utility.Control.ExecuteCommand(cmdstr);
}

function is_valid_address(address) {
    return address > 0x100000; // todo: should be some high value;
}

function is_valid_function_address(address, dll_base_start, dll_base_end) {
    return address >= dll_base_start && address <= dll_base_end;
}

function find_all_coro_frames(coro_fn_addres, first_n) {
    var lines = exec("!mex.fel -x \"dq 0x${@#Line}+0x40 L1\"  !mex.head -n " + first_n + " !mex.cut -f 5 !mex.grep busy !ext.heap -srch " + coro_fn_addres);
    var parent_coro_frames = [];
    for (line of lines) {
        if (!line) {
            continue;
        }

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

function walk_parent_chain(child, call_stack_depth, dll_base_start, dll_base_end) {
    if (call_stack_depth <= 0) {
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

        if (!is_valid_address(parent_coro_address) || !is_valid_function_address(parseInt(parent_fn_address, 16), dll_base_start, dll_base_end)) {
            return [child];
        }

        // log("  > " + parent_coro_address_str + " " + parent_fn_address);
        var stack = walk_parent_chain({co_address: parent_coro_address, fn_address: parent_fn_address}, call_stack_depth - 1, dll_base_start, dll_base_end);
        stack.push(child);
        return stack;
    }
    catch (ex)
    {
        // log("second: " + ex);
    }

    return [child];
}
