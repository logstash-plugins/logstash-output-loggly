# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/loggly"

describe 'outputs/loggly' do
  let(:config) { { 'key' => 'abcdef123456' } }
  let(:event) { LogStash::Event.new({'message' => 'fanastic log entry', 'source' => 'someapp', 'type' => 'nginx',
                                     '@timestamp' => LogStash::Timestamp.now}) }

  context 'when initializing' do
    subject { LogStash::Outputs::Loggly.new(config) }

    it 'should register' do
      expect { subject.register }.to_not raise_error
    end

    it 'should have default config values' do
      insist { subject.proto } == 'http'
      insist { subject.host } == 'logs-01.loggly.com'
      insist { subject.tag } == 'logstash'
    end
  end

  context "when outputting messages" do
    it 'should support field interpolation on key' do
      # add a custom key value for Loggly config
      event['token'] = 'xxxxxxx1234567'
      config['key'] = '%{token}'

      output = LogStash::Outputs::Loggly.new(config)
      allow(output).to receive(:send_event).with("http://logs-01.loggly.com/inputs/xxxxxxx1234567/tag/logstash", event.to_json)
      output.receive(event)
    end

    it 'should set the default tag to logstash' do
      output = LogStash::Outputs::Loggly.new(config)
      allow(output).to receive(:send_event).with("http://logs-01.loggly.com/inputs/abcdef123456/tag/logstash", event.to_json)
      output.receive(event)
    end
  
    it 'should support field interpolation for tag' do
      config['tag'] = '%{source}'
      output = LogStash::Outputs::Loggly.new(config)
      allow(output).to receive(:send_event).with("http://logs-01.loggly.com/inputs/abcdef123456/tag/someapp", event.to_json)
      output.receive(event)
    end

    it 'should default tag to logstash if interpolated field does not exist' do
      config['tag'] = '%{foobar}'
      output = LogStash::Outputs::Loggly.new(config)
      allow(output).to receive(:send_event).with("http://logs-01.loggly.com/inputs/abcdef123456/tag/logstash", event.to_json)
      output.receive(event)
    end
  end
end
