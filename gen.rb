#!/usr/bin/env ruby

#
# gen.rb: Benchmark OpenSSL ciphers on several systems, then do
# the following:
#
#   * aggregate the results as CSV files
#   * create SVG charts of the results
#   * generate HTML fragments for the SVG results
#
# Usage: ./gen.rb config.yaml
#
# See included `config.yaml` for configuration options
#

require 'fileutils'
require 'yaml'
require 'csv'
require 'logger'
require 'json'

module Tentacle
  # block sizes
  SIZES = %w{16 64 256 1024 8192 16384}

  #
  # list of tests to run.
  #
  TESTS = [{
    name: 'lscpu',
    exec: %w{lscpu},
  }, {
    name: 'version',
    exec: %w{openssl version},
  }, {
    name: 'speed',
    exec: %w{openssl speed -mr -evp},
    type: 'algos', # run test for each algorithm
  }]

  #
  # Default list of EVP algorithms.
  #
  # removed sha3-256 because it is not supported in older versions of
  # openssl
  ALGOS = %w{
    blake2b512
    blake2s256
    sha256
    sha512
    aes-128-cbc
    aes-192-cbc
    aes-256-cbc
  }

  #
  # Map of type to column headers.
  #
  # Used to generate CSV and HTML table column headers.
  #
  COLS = {
    all: [{
      id:   'host',
      name: 'host',
    }, {
      id:   'algo',
      name: 'algo',
    }, {
      id:   'size',
      name: 'size',
    }, {
      id:   'speed',
      name: 'speed',
    }],

    algo: [{
      id:   'host',
      name: 'host',
    }, {
      id:   'size',
      name: 'size',
    }, {
      id:   'speed',
      name: 'speed',
    }],

    # columns for csvs/hosts.csv and html/hosts.html
    hosts: [{
      id:   'name',
      name: 'Name',
    }, {
      id:   'arch',
      name: 'Architecture',
    }, {
      id:   'text',
      name: 'Description',
    }],
  }.freeze

  #
  # Architecture titles format strings.
  #
  ARCH_TITLES = {
    all: 'OpenSSL Speed: All Systems, %s',
    arm: 'OpenSSL Speed: Raspberry Pis, %s',
    x86: 'OpenSSL Speed: x86-64, %s',
  }

  HTML = {
    all: %{
      <table class='table table-hover'>
        <thead>
          <tr>%s</tr>
        </thead>

        <tbody>
          %s
        </tbody>
      </table>
    }.strip,

    col: %{
      <th>%s</th>
    }.strip,

    row: %{
      <tr>%s</tr>
    }.strip,

    cell: %{
      <td>%s</td>
    }.strip,

    svg: %{
      <p><img
        src="%s"
        width="100%%"
        height="auto"
        title="%s"
        alt="%s"
      /></p>
    }.strip,
  }.freeze

  module BG
    #
    # Generate SSH command.
    #
    def ssh(host, cmd)
      ['/usr/bin/ssh', host, *cmd]
    end

    #
    # Spawn background task that writes output to given file and return
    # the PID.
    #
    def bg(out, cmd)
      @log.debug('bg') do
        JSON.unparse({
          out: out,
          cmd: cmd,
        })
      end

      spawn(*cmd,
        in: '/dev/null',
        out: out,
        err: '/dev/null',
        close_others: true
      )
    end
  end

  class HostQueue
    include BG

    def self.run(log, queues)
      new(log, queues).run
    end

    def initialize(log, queues)
      @log, @queues = log, queues
      @pids = {}
    end

    #
    # Run until all commands have been run successfully on all hosts, or
    # until any command on any host fails.
    #
    def run
      @queues.keys.each do |host|
        drain(host)
      end

      until done?
        @log.debug('HostQueue#run') do
          'Process.wait(): %s ' % [JSON.unparse({
            pids: @pids,
            queues: @queues,
          })]
        end

        # get pid and status of child that exited
        pid = Process.wait(-1, Process::WUNTRACED)
        st = $?

        # map pid to host
        if host = @pids.delete(pid)
          if st.success?
            # log success
            @log.debug('HostQueue#run') do
              'command done: %s' % [JSON.unparse({
                host: host,
                pid:  pid,
              })]
            end
          else
            # build error message
            err = 'command failed: %s' % [JSON.unparse({
              host: host,
              pid:  pid,
            })]

            # log and raise error
            @log.fatal('HostQueue#run') { err }
            raise err
          end

          # start next command from host
          drain(host)
        end
      end
    end

    private

    #
    # Start next queued command from given host.
    #
    def drain(host)
      # get queue for host
      queue = @queues[host]
      return unless queue && queue.size > 0

      # drain host queue of commands that can be skipped
      while queue.size > 0 && File.exists?(queue.first[:out])
        @log.debug('HostQueue#drain') do
          'skipping command: %s' % [JSON.unparse({
            host: host,
            row:  queue.first
          })]
        end

        # remove skipped command
        queue.shift
      end

      if row = queue.shift
        # invoke task, grab pid
        pid = bg(row[:out], ssh(host, row[:cmd]))

        # log task
        @log.debug('HostQueue#drain') do
          JSON.unparse({
            host: host,
            row:  row,
            pid:  pid,
          })
        end

        # add pid to pid to host map
        @pids[pid] = host
      end

      nil
    end

    def done?
      @pids.size == 0 && @queues.keys.all? { |k| @queues[k].size == 0 }
    end
  end

  class Runner
    include BG

    #
    # Allow one-shot invocation.
    #
    def initialize(config)
      # cache config
      @config = config

      # get log level
      log_level = (@config['log_level'] || 'info').upcase

      # create logger and set log level
      @log = ::Logger.new(STDERR)
      @log.level = ::Logger.const_get(log_level)
      @log.debug { "log level = #{log_level}" }
    end

    #
    # Run benchmarks (if necessary) and generate output CSVs and SVGs.
    #
    def run
      # create output directories
      make_output_dirs

      # connect to hosts in background, wait for all to complete
      spawn_benchmarks

      # generate CSVs, SVGs, and HTML fragments, wait for all to
      # complete
      save(parse_data)

      # generate hosts.{html,csv}
      save_hosts.each { |t| t.join }
    end

    private

    #
    # Create output directories
    #
    def make_output_dirs
      dirs = (%w{html csvs svgs} + @config['hosts'].map { |row|
        'hosts/%s' % [row['name']]
      }).map { |dir|
        '%s/%s' % [out_dir, dir]
      }

      @log.debug { 'creating output dirs: %s' % [dirs.join(', ')] }
      FileUtils.mkdir_p(dirs)
    end

    #
    # Spawn benchmarks in background and return a list of PIDs.
    #
    def spawn_benchmarks
      # build map of hosts to commands
      queues = @config['hosts'].reduce(Hash.new do |h, k|
        h[k] = []
      end) do |r, row|
        TESTS.reduce(r) do |r, test|
          case test[:type]
          when 'algos'
            # queue test command for each algorithm
            (@config['algos'] || ALGOS).reduce(r) do |r, algo|
              r[row['host']] << {
                cmd: [*test[:exec], algo],
                out: '%s/hosts/%s/%s-%s.txt' % [
                  out_dir,
                  row['name'],
                  test[:name],
                  algo,
                ],
              }

              r
            end
          else
            # queue command for test
            r[row['host']] << {
              cmd: test[:exec],
              out: '%s/hosts/%s/%s.txt' % [
                out_dir,
                row['name'],
                test[:name],
              ]
            }

            r
          end
        end
      end

      # block until all tasks have exited
      HostQueue.run(@log, queues)
    end

    #
    # Parse openssl benchmark data into a map of algorithm => rows
    #
    def parse_data
      @config['hosts'].reduce(Hash.new do |h, k|
        h[k] = Hash.new do |h2, k2|
          h2[k2] = { max: 0, rows: [] }
        end
      end) do |r, row|
        # build absolute path to openssl speed data files
        glob = '%s/hosts/%s/speed-*.txt' % [out_dir, row['name']]

        # parse speed files
        Dir[glob].each do |path|
          # get arch
          arch = row['pi'] ? 'arm' : 'x86'

          # parse file
          lines = File.readlines(path).select { |line|
            # match on result rows
            line =~ /^\+F:/
          }.each do |line|
            # split to results
            vals = line.strip.split(':')

            # build algorithm name
            algo = vals[2].gsub(/\s+/, '-')

            # walk block sizes
            SIZES.each_with_index do |size, i|
              [{
                algo: 'all',
                arch: 'all',
              }, {
                algo: algo,
                arch: 'all',
              }, {
                algo: 'all',
                arch: arch,
              }, {
                algo: algo,
                arch: arch,
              }].each do |agg|
                val = vals[i + 3].to_f
                max = r[agg[:arch]][agg[:algo]][:max]
                r[agg[:arch]][agg[:algo]][:max] = val if val > max

                r[agg[:arch]][agg[:algo]][:rows] << if agg[:algo] == 'all'
                  # build row for all-*.csv
                  [row['name'], algo, size, val]
                else
                  # row for algo-specific CSV
                  [row['name'], size, val]
                end
              end
            end
          end
        end

        r
      end
    end

    #
    # Generate CSVs, SVGs, and HTML fragments, then wait for them all
    # to complete.
    #
    def save(all_data, &block)
      # build svg lut
      svgs = Hash.new { |h, k| h[k] = [] }

      # generate csvs and svgs, then wait for them to complete
      join('save', all_data.reduce([]) do |r, pair|
        arch, algo_hash = pair

        algo_hash.reduce(r) do |r, pair|
          algo, data = pair

          # save csv
          csv_path = save_csv(arch, algo, data[:rows])

          if algo != 'all'
            # start building svg
            max = get_max_value(all_data, arch, algo)
            row = save_svg(arch, algo, max, csv_path)
            r << row[:pid]

            # add to svg lut
            svgs[arch] << {
              algo: algo,
              svg: row[:svg],
              title: row[:title],
            }
          end

          # return pids
          r
        end
      end)

      # generate html fragments for svgs
      save_html(svgs)
    end

    #
    # Generate HTML fragments for each architecture.
    #
    def save_html(svgs)
      svgs.each do |arch, rows|
        # build path to html fragment
        path = '%s/html/%s.html' % [out_dir, arch]

        # write html
        File.write(path, rows.sort { |a, b|
          a[:svg] <=> b[:svg]
        }.map { |row|
          svg_path = '../svgs/%s' % [File.basename(row[:svg])]
          HTML[:svg] % [svg_path, row[:title], row[:title]]
        }.join)
      end
    end

    #
    # Generate CSV and HTML table of hosts and return array of threads.
    #
    def save_hosts
      [save_hosts_csv, save_hosts_html]
    end

    #
    # Generate out/csvs/hosts.csv and return thread.
    #
    def save_hosts_csv
      Thread.new do
        # build csv path
        path = '%s/csvs/hosts.csv' % [out_dir]

        # save CSV
        CSV.open(path, 'wb') do |csv|
          # write headers
          csv << COLS[:hosts].map { |col| col[:name] }

          # write rows
          @config['hosts'].each do |row|
            csv << COLS[:hosts].map { |col| row[col[:id]] }
          end
        end
      end
    end

    #
    # Generate out/html/hosts.html and return thread.
    #
    def save_hosts_html
      Thread.new do
        # build html path
        path = '%s/html/hosts.html' % [out_dir]

        # generate and save html
        File.write(path, HTML[:all] % [
          COLS[:hosts].map { |col|
            HTML[:col] % [col[:name]]
          }.join,

          @config['hosts'].map { |row|
            HTML[:row] % [COLS[:hosts].map { |col|
              HTML[:cell] % [row[col[:id]]]
            }.join]
          }.join,
        ])
      end
    end

    #
    # save CSV of rows.
    #
    def save_csv(arch, algo, rows)
      # build path to output csv
      csv_path = '%s/csvs/%s-%s.csv' % [out_dir, arch, algo]

      # write csv
      CSV.open(csv_path, 'wb') do |csv|
        # write column headers
        csv << COLS[(algo == 'all') ? :all : :algo].map { |col| col[:id] }

        # write rows
        rows.each do |row|
          csv << row
        end
      end

      # return csv path
      csv_path
    end

    #
    # Render CSV as SVG in background and return SVG and PID.
    #
    def save_svg(arch, algo, max, csv_path)
      plot_path = '%s/plot.py' % [__dir__]
      svg_path = '%s/svgs/%s-%s.svg' % [out_dir, arch, algo]

      # make chart title
      title = ARCH_TITLES[arch.intern] % [algo]

      # calculate xlimit (round up to nearest 100)
      # xlimit = ((algo =~ /^aes/) ? 400 : 2000).to_s
      xlimit = (max / (1048576 * 50.0)).ceil * 50

      # build plot command
      plot_cmd = [
        '/usr/bin/python3',
        plot_path,
        csv_path,
        svg_path,
        title,
        xlimit.to_s,
      ]

      # return svg path and pid
      {
        # create svg in background
        pid: bg('/dev/null', plot_cmd),
        svg: svg_path,
        title: title,
      }
    end

    #
    # get maximum value depending for chart
    #
    def get_max_value(data, arch, algo)
      is_aes = is_aes?(algo)

      data['all'].keys.select { |k|
        is_aes == is_aes?(k)
      }.map { |k|
        data[arch][k][:max]
      }.reduce(0) { |rm, v|
        v > rm ? v : rm
      }
    end

    #
    # Is the given algorithm AES?
    #
    def is_aes?(algo)
      @is_aes_cache ||= {}
      @is_aes_cache[algo] ||= !!(algo =~ /^aes/)
    end

    #
    # join set of PIDs together
    #
    def join(set_name, pids = [])
      @log.debug('join') do
        JSON.unparse({
          set_name: set_name,
          pids: pids,
        })
      end

      # wait for all tasks to complete and check for errors
      errors = pids.reduce([]) do |r, pid|
        Process.wait(pid)
        $?.success? ? r : (r << pid)
      end

      if errors.size > 0
        # build error message
        err = 'pids failed: %s' % [JSON.unparse({
          set_name: set_name,
          pids: errors,
        })]

        # log and raise error
        @log.fatal('join') { err }
        raise err
      end
    end

    #
    # Get output directory.
    #
    def out_dir
      @config['out_dir']
    end
  end
  #
  # Allow one-shot invocation.
  #
  def self.run(app, args)
    # check command-line arguments
    unless config_path = args.shift
      raise "Usage: #{app} config.yaml"
    end

    Runner.new(load_config(config_path)).run
  end

  #
  # Load config file and check for required keys.
  #
  def self.load_config(path)
    # read/check config
    ::YAML.load_file(path).tap do |r|
      # check for required config keys
      missing = %w{out_dir hosts}.reject { |key| r.key?(key) }
      raise "Missing required config keys: #{missing}" if missing.size > 0
    end
  end
end

# allow cli invocation
Tentacle.run($0, ARGV) if __FILE__ == $0
