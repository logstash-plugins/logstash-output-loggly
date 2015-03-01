# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/loggly"

describe 'outputs/loggly' do
  let(:config) { { "key" => '34567d8-2b67-567-fghj-6789' } }
  let(:event) { LogStash::Event.new({'message' => 'fanastic log entry', 'source' => 'someapp', 'type' => 'nginx',
                                     '@timestamp' => LogStash::Timestamp.now}) }

  context 'when initializing' do
    it 'should register' do
      output = LogStash::Outputs::Loggly.new(config)
      expect {output.register}.to_not raise_error
    end

    it 'should populate config with defalt values' do
      output = LogStash::Outputs::Loggly.new(config)
      insist { output.proto } == 'http'
      insist { output.host } == 'logs-01.loggly.com'
      insist { output.tag } == 'logstash'
    end
  end

  context "when outputting messages" do
    it 'should support field interpolation for key' do
      event['token'] = '5678-ty67-hbj6789-9876h'
      config['key'] = "%{token}"
      output = LogStash::Outputs::Loggly.new(config)
      expected_message = event.to_json
      output.should_receive(:send_event).with("http://logs-01.loggly.com/inputs/5678-ty67-hbj6789-9876h/tag/logstash", expected_message)
      output.receive(event)
    end

    it 'should set the default tag to logstash' do
      output = LogStash::Outputs::Loggly.new(config)
      expected_message = event.to_json
      insist { output.format_message(event) } == expected_message
      output.should_receive(:send_event).with("http://logs-01.loggly.com/inputs/34567d8-2b67-567-fghj-6789/tag/logstash", expected_message)
      output.receive(event)
    end
  
    it 'should support field interpolation for tag' do
      config['tag'] = "%{source}"
      output = LogStash::Outputs::Loggly.new(config)
      expected_message = event.to_json
      insist { output.format_message(event) } == expected_message
      output.should_receive(:send_event).with("http://logs-01.loggly.com/inputs/34567d8-2b67-567-fghj-6789/tag/someapp", expected_message)
      output.receive(event)
    end

    it 'should default tag to logstash if interpolated field does not exist' do
      config['tag'] = "%{foobar}"
      output = LogStash::Outputs::Loggly.new(config)
      expected_message = event.to_json
      insist { output.format_message(event) } == expected_message
      output.should_receive(:send_event).with("http://logs-01.loggly.com/inputs/34567d8-2b67-567-fghj-6789/tag/logstash", expected_message)
      output.receive(event)
    end
  end
end
