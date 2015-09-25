# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "uri"
# TODO(sissel): Move to something that performs better than net/http
require "net/http"
require "net/https"


# Ugly monkey patch to get around http://jira.codehaus.org/browse/JRUBY-5529
Net::BufferedIO.class_eval do
    BUFSIZE = 1024 * 16

    def rbuf_fill
      timeout(@read_timeout) {
        @rbuf << @io.sysread(BUFSIZE)
      }
    end
end

# Got a loggly account? Use logstash to ship logs to Loggly!
#
# This is most useful so you can use logstash to parse and structure
# your logs and ship structured, json events to your account at Loggly.
#
# To use this, you'll need to use a Loggly input with type 'http'
# and 'json logging' enabled.
class LogStash::Outputs::Loggly < LogStash::Outputs::Base
  config_name "loggly"

  # The hostname to send logs to. This should target the loggly http input
  # server which is usually "logs-01.loggly.com" (Gen2 account).
  # See Loggly HTTP endpoint documentation at
  # https://www.loggly.com/docs/http-endpoint/
  config :host, :validate => :string, :default => "logs-01.loggly.com"

  # The loggly http input key to send to.
  # This is usually visible in the Loggly 'Inputs' page as something like this:
  # ....
  #     https://logs.hoover.loggly.net/inputs/abcdef12-3456-7890-abcd-ef0123456789
  #                                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  #                                           \---------->   key   <-------------/
  # ....
  # You can use `%{foo}` field lookups here if you need to pull the api key from
  # the event. This is mainly aimed at multitenant hosting providers who want
  # to offer shipping a customer's logs to that customer's loggly account.
  config :key, :validate => :string, :required => true

  # Should the log action be sent over https instead of plain http
  config :proto, :validate => :string, :default => "http"

  # Loggly Tag
  # Tag helps you to find your logs in the Loggly dashboard easily
  # You can make a search in Loggly using tag as "tag:logstash-contrib"
  # or the tag set by you in the config file.
  #
  # You can use %{somefield} to allow for custom tag values.
  # Helpful for leveraging Loggly source groups.
  # https://www.loggly.com/docs/source-groups/
  config :tag, :validate => :string, :default => "logstash"

  # Proxy Host
  config :proxy_host, :validate => :string

  # Proxy Port
  config :proxy_port, :validate => :number

  # Proxy Username
  config :proxy_user, :validate => :string

  # Proxy Password
  config :proxy_password, :validate => :password, :default => ""


  public
  def register
    # nothing to do
  end

  public
  def receive(event)
    return unless output?(event)

    return if event == LogStash::SHUTDOWN

    key = event.sprintf(@key)
    tag = event.sprintf(@tag)

    # For those cases where %{somefield} doesn't exist
    # we should ship logs with the default tag value.
    tag = 'logstash' if /^%{\w+}/.match(tag)

    # Send event
    send_event("#{@proto}://#{@host}/inputs/#{key}/tag/#{tag}", format_message(event))
  end # def receive

  public
  def format_message(event)
    event.to_json
  end

  private
  def send_event(url, message)
    url = URI.parse(url)
    @logger.info("Loggly URL", :url => url)

    http = Net::HTTP::Proxy(@proxy_host,
                            @proxy_port,
                            @proxy_user,
                            @proxy_password.value).new(url.host, url.port)

    if url.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    # post message
    request = Net::HTTP::Post.new(url.path)
    request.body = message
    response = http.request(request)

    if response.is_a?(Net::HTTPSuccess)
      @logger.info("Event send to Loggly OK!")
    else
      @logger.warn("HTTP error", :error => response.error!)
    end
  end # def send_event

end # class LogStash::Outputs::Loggly

