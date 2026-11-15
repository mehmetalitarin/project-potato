"""Feature modules: the tools the assistant can use.

So far: ``portfolio``, which lists, records and removes holdings, and
``link_analysis``, which checks a link's text for signs of phishing.

Planned: application launcher, calendar and homework summaries, and the
read-only security monitors.

Boundary: a module runs only when ``potato.security`` hands it a validated
call. Modules never run directly from model output.
"""
