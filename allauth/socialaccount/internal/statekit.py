"""
Multi-slot OAuth ``state`` storage.

Backported from upstream django-allauth's ``statekit`` module so that several
OAuth flows can be in-flight within a single session without clobbering each
other. Each flow's state (including its PKCE ``code_verifier``) is stored under
its own random ``state_id`` inside the ``socialaccount_states`` session dict,
rather than the legacy single ``socialaccount_state`` slot. Old entries are
garbage collected by TTL and a hard cap on the number of concurrent states.
"""

import time

from django.utils.crypto import get_random_string


STATE_ID_LENGTH = 16
MAX_STATES = 10
STATE_TTL = 600
STATES_SESSION_KEY = "socialaccount_states"
# allauth 0.50.0's single-slot key. Kept for backward compatibility: callers
# that stashed under the old key (Platform's custom non-oauth2 providers such
# as ssoclient and saml2) must still be able to recover their state.
LEGACY_STATE_SESSION_KEY = "socialaccount_state"


def _mark_modified(request):
    # Real Django SessionStore needs an explicit ``modified`` flag because we
    # mutate the states dict in place (same object reference). A plain dict
    # session — used by some custom providers' tests — has no such attribute,
    # so guard the write rather than assume a SessionStore.
    session = request.session
    if hasattr(session, "modified"):
        session.modified = True


def get_oldest_state(states, rev=False):
    oldest_ts = None
    oldest_id = None
    oldest = None
    for state_id, state_ts in states.items():
        ts = state_ts[1]
        if oldest_ts is None or (
            (rev and ts > oldest_ts) or ((not rev) and oldest_ts > ts)
        ):
            oldest_ts = ts
            oldest_id = state_id
            oldest = state_ts[0]
    return oldest_id, oldest


def gc_states(states):
    now = time.time()
    expired_sids = [sid for sid, (_, ts) in states.items() if now - ts > STATE_TTL]
    for sid in expired_sids:
        del states[sid]
    if len(states) > MAX_STATES:
        oldest_id, oldest = get_oldest_state(states)
        if oldest_id:
            del states[oldest_id]


def get_states(request):
    states = request.session.get(STATES_SESSION_KEY)
    if not isinstance(states, dict):
        states = {}
    return states


def stash_state(request, state, state_id=None):
    states = get_states(request)
    gc_states(states)
    if state_id is None:
        state_id = get_random_string(STATE_ID_LENGTH)
    states[state_id] = (state, time.time())
    request.session[STATES_SESSION_KEY] = states
    _mark_modified(request)
    return state_id


def peek_state(request, state_id):
    """Return a stashed state without consuming it (honouring the TTL)."""
    states = get_states(request)
    state_ts = states.get(state_id)
    if state_ts is None:
        return None
    state, ts = state_ts
    if time.time() - ts > STATE_TTL:
        return None
    return state


def unstash_state(request, state_id):
    state = None
    states = get_states(request)
    state_ts = states.get(state_id)
    if state_ts is not None:
        state, ts = state_ts
        if time.time() - ts > STATE_TTL:
            state = None
        del states[state_id]
        request.session[STATES_SESSION_KEY] = states
        _mark_modified(request)
    return state


def _unstash_legacy_state(request):
    """Recover (and consume) state stored under allauth 0.50.0's single slot.

    0.50.0 stored ``(state, verifier)``; a real session JSON-round-trips the
    tuple into a list. Return just the ``state`` payload, matching the old
    ``SocialLogin.unstash_state`` contract.
    """
    legacy = request.session.get(LEGACY_STATE_SESSION_KEY)
    if legacy is None:
        return None
    del request.session[LEGACY_STATE_SESSION_KEY]
    _mark_modified(request)
    if isinstance(legacy, (tuple, list)) and len(legacy) == 2:
        return legacy[0]
    return legacy


def unstash_last_state(request):
    states = get_states(request)
    state_id, state = get_oldest_state(states, rev=True)
    if state_id:
        unstash_state(request, state_id)
        return state
    # No multi-slot state — fall back to the legacy single slot so callers that
    # stashed the old way (custom non-oauth2 providers) still recover.
    return _unstash_legacy_state(request)
