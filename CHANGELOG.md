## 5.0.0
  - This version introduces "breaking" changes for users who never copied/renamed
    their `@timestamp` field to `timestamp`: their events will suddenly appear
    in Loggly with a `timestamp` based on Logstash's value of `@timestamp`.
    This would especially be noticed at times where processing is behind, and
    events need to be "backfilled".
    - The plugin now sets field `timestamp` so that Loggly will recognize the
      correct timestamp.
      - The event's timestamps will however not be touched at all if `timestamp`
        is already set on the event or if `@timestamp` is missing.
    - This version introduces attribute `convert_timestamp` (defaults to true), which
      triggers the timestamp mingling.
  - Now log a debug message with all of the plugin's configuration upon initialization.

## 4.0.0
  - The plugin now uses the Loggly bulk API.
  - If you need to modify event batch sizes and max delay between flushes,
    please adjust the Logstash settings `pipeline.batch.size` and
    `pipeline.batch.delay` respectively.
  - New settings: `max_event_size` and `max_payload_size`.
    Both are currently set according to Loggly's [published API limits](https://www.loggly.com/docs/http-bulk-endpoint/).
    They only need to be changed if Loggly changes these limits.
  - The plugin now skips events bigger than the API limit for single event size.
    A proper warning is logged when this happens.
  - When interpolating `key` field, drop messages where interpolation doesn't
    resolve (meaning we don't have the API key for the event).
  - When interpolating `tag` field, revert to default of 'logstash' if interpolation doesn't resolve.
  - Beef up unit tests significantly.
  - See pull request [#29](https://github.com/logstash-plugins/logstash-output-loggly/pull/29) for all details.

## 3.0.5
  - [#24](https://github.com/logstash-plugins/logstash-output-loggly/pull/24)
    Get rid of a Ruby warning from using `timeout`.
  - [#26](https://github.com/logstash-plugins/logstash-output-loggly/pull/26)
    Docs: Better directions for getting a key in Loggly & other cleanups.
  - [#26](https://github.com/logstash-plugins/logstash-output-loggly/pull/26)
    Get rid of a few `puts` and reduce the noise at logging level `info`.
    There is no longer 1+ log/stdout line created for every event ingested.

## 3.0.4
  - Docs: Set the default\_codec doc attribute.

## 3.0.3
  - Update gemspec summary

## 3.0.2
  - Fix some documentation issues

## 3.0.0
 - update to the new plugin api
 - update travis.yml
 - relax contraints on logstash-core-plugin-api

## 2.0.5
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.4
  - New dependency requirements for logstash-core for the 5.0 release

## 2.0.3
 - Adding exception handling and retries

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
