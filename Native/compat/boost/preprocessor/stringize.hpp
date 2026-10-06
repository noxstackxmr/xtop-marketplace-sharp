#pragma once
// Minimal stringization adapter used only by Monero's warning pragmas.
// No Boost library or cryptographic code is replaced by this adapter.
#define XTOP_STRINGIZE_IMPL(value) #value
#define BOOST_PP_STRINGIZE(value) XTOP_STRINGIZE_IMPL(value)
