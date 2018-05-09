# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/outputs/loggly'

def logger_for(plugin)
  plugin.instance_variable_get('@logger')
end

describe 'outputs/loggly' do
  let(:config) { { 'key' => 'abcdef123456' } }

  let(:output) do
    LogStash::Outputs::Loggly.new(config).tap do |output|
      output.register
    end
  end

  let(:event) do
    LogStash::Event.new(
      'message' => 'fantastic log entry',
      'source' => 'someapp',
      'type' => 'nginx',
      '@timestamp' => LogStash::Timestamp.now)
  end

  context 'when initializing' do
    subject { LogStash::Outputs::Loggly.new(config) }

    it 'should register' do
      expect { subject.register }.to_not raise_error
    end

    it 'should have default config values' do
      expect(subject.proto).to eq('http')
      expect(subject.host).to eq('logs-01.loggly.com')
      expect(subject.tag).to eq('logstash')
      expect(subject.max_event_size).to eq(1_048_576)
      expect(subject.max_payload_size).to eq(5_242_880)
    end
  end

  context 'when sending events' do
    it 'should set the default tag to logstash' do
      expect(output).to receive(:send_batch).with([{event: event, key: 'abcdef123456', tag: 'logstash'}])
      output.receive(event)
    end

    it 'should support field interpolation on key' do
      # add a custom key value for Loggly config
      event.set('token', 'xxxxxxx1234567')
      config['key'] = '%{token}'

      expect(output).to receive(:send_batch).with([{event: event, key: 'xxxxxxx1234567', tag: 'logstash'}])
      output.receive(event)
    end

    it 'should support field interpolation for tag' do
      config['tag'] = '%{source}'
      expect(output).to receive(:send_batch).with([{event: event, key: 'abcdef123456', tag: 'someapp'}])
      output.receive(event)
    end

    it 'should default tag to logstash if interpolated field for tag does not exist' do
      config['tag'] = '%{foobar}'
      expect(output).to receive(:send_batch).with([{event: event, key: 'abcdef123456', tag: 'logstash'}])
      output.receive(event)
    end

    it 'should drop messages where interpolated field for key does not exist' do
      config['key'] = '%{custom_key}'
      event.set('custom_key', 'a_key')
      event2 = event.clone
      event2.remove('custom_key')

      expect(output).to receive(:send_batch).once.with([{event: event, key: 'a_key', tag: 'logstash'}, nil])
      logger = logger_for(output)
      expect(logger).to receive(:warn).with(/No key provided/)
      expect(logger).to receive(:debug).with(/Dropped message/, kind_of(Hash))

      output.multi_receive([event, event2])
    end

    context 'with different combinations of key and tag' do
      it 'should perform one http request per batch of common key+tag' do
        config['key'] = '%{custom_key}'
        config['tag'] = '%{custom_tag}'
        event.set('custom_key', 'generally_used_key')

        event1 = event.clone.tap { |e| e.set('message', 'event1') }
        event2 = event.clone.tap { |e| e.set('message', 'event2') ; e.set('custom_key', 'other_key') }
        event3 = event.clone.tap { |e| e.set('message', 'event3') ; e.set('custom_tag', 'other_tag') }
        event4 = event.clone.tap { |e| e.set('message', 'event4') }

        expect(output).to receive(:perform_api_call) { |url, body|
          expect(body).to match /"event1"/
          expect(body).to match /"event4"/
          expect(url).to eq('http://logs-01.loggly.com/bulk/generally_used_key/tag/logstash')
        }
        expect(output).to receive(:perform_api_call) { |url, body|
          expect(body).to match /"event2"/
          expect(url).to eq('http://logs-01.loggly.com/bulk/other_key/tag/logstash')
        }
        expect(output).to receive(:perform_api_call) { |url, body|
          expect(body).to match /"event3"/
          expect(url).to eq('http://logs-01.loggly.com/bulk/generally_used_key/tag/other_tag')
        }
        expect(output).not_to receive(:perform_api_call) # anymore

        output.multi_receive([event1, event2, event3, event4])
      end
    end
  end

  context 'splitting batches of events' do
    context 'when they are all with the same key+tag' do
      it 'should return one batch' do
        batches = output.split_batches([ {event: :event1, key: 'key1', tag: 'tag1'},
                                         {event: :event2, key: 'key1', tag: 'tag1'} ])
        expect(batches.size).to eq(1)
        expect(batches).to eq({ ['key1', 'tag1'] => [:event1, :event2] })
      end
    end

    context 'when messages have different key & tag' do
      it 'should return one batch for each key+tag combination' do
        batches = output.split_batches([
          {event: :event1, key: 'key1', tag: 'tag1'},
          {event: :event2, key: 'key2', tag: 'tag1'},
          {event: :event3, key: 'key2', tag: 'tag2'},
          {event: :event4, key: 'key1', tag: 'tag1'},
          {event: :event5, key: 'key2', tag: 'tag1'},
          {event: :event6, key: 'key1', tag: 'tag1'},
          {event: :event7, key: 'key1', tag: 'tag1'},
        ])
        expect(batches.size).to eq(3)
        expect(batches).to eq(
          { ['key1', 'tag1'] => [:event1, :event4, :event6, :event7],
            ['key2', 'tag1'] => [:event2, :event5],
            ['key2', 'tag2'] => [:event3],
          })
      end
    end
  end

  context 'when building message bodies' do
    it 'should send only one payload when everything fits' do
      yielded_times = 0
      output.build_message_bodies([event] * 10) do |body|
        expect(body.lines.count).to eq(10)

        yielded_times += 1
      end
      expect(yielded_times).to eq(1)
    end

    it 'should skip events that are bigger than max_event_size' do
      config['max_event_size'] = 1024
      good_event = LogStash::Event.new('message' => 'fantastic log entry',
                                       'source' => 'someapp',
                                       'type' => 'nginx',
                                       '@timestamp' => LogStash::Timestamp.now)
      big_event = good_event.clone.tap { |e| e.set('filler', 'helloworld' * 100) }

      logger = logger_for output
      expect(logger).to receive(:warn).once.with(
        /Skipping event/, hash_including(:event_size => 1134,
                                         :max_event_size => 1024))
      expect(logger).to receive(:debug).twice

      yielded_times = 0
      output.build_message_bodies([good_event, big_event]) do |body|
        expect(body.lines.count).to eq(1)
        expect(body).not_to match /helloworld/

        yielded_times += 1
      end
      expect(yielded_times).to eq(1)
    end

    it 'should yield as many times as needed to send appropriately-sized payloads' do
      config['max_payload_size'] = 1024
      # Once JSON-encoded, these events are 122 bytes each.
      # 8 of them fit in a 1024 bytes payload
      event = LogStash::Event.new('message' => 'fantastic log entry',
                                  'source' => 'someapp',
                                  'type' => 'nginx',
                                  '@timestamp' => LogStash::Timestamp.now)

      payloads = []
      output.build_message_bodies([event] * 10) do |body|
        payloads << body
      end
      expect(payloads.size).to eq(2)
      expect(payloads[0].lines.count).to eq(8)
      expect(payloads[1].lines.count).to eq(2)
    end
  end
end
