"""Feature modules: the tools the assistant can use.

So far: ``portfolio``, which lists, records and removes holdings;
``link_analysis``, which checks a link's text for signs of phishing;
``launcher``, which opens one of a fixed list of Apple's applications; and
``calendar``, which lists upcoming events and deadlines, read-only.

Planned: the read-only security monitors.

Boundary: a module runs only when ``potato.security`` hands it a validated
call. Modules never run directly from model output.
"""
