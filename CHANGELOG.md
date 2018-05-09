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
