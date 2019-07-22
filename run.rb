#!/usr/bin/env ruby

#
# run.rb: Benchmark OpenSSL ciphers on several systems, then do
# the following:
#
#   * aggregate the results as CSV files
#   * create SVG charts of the results
#   * generate HTML fragments for the SVG results
#
# Usage: ./run.rb config.yaml
#
# See included `config.yaml` for configuration options
#

require 'fileutils'
require 'yaml'
require 'csv'
require 'logger'
require 'json'
require 'luigi-template'

module PiBench
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
    }, {
      id:   'openssl',
      name: 'OpenSSL Version',
    }],
  }.freeze

  #
  # Architecture strings.
  #
  ARCHS = {
    all: {
      name: 'All',
      text: %{
        <p>
          Test results for all systems.  Note that the x86-64 systems
          include AES-NI and SHA2 hardware acceleration.
        </p>
      }.strip,
    },

    arm: {
      name: 'Pis',
      text: %{
        <p>
          Test results for Raspberry Pi systems only.
        </p>
      }.strip,
    },

    x86: {
      name: 'x86-64',
      text: %{
        <p>
          Test results for x86-64 systems only.
        </p>
      }.strip,
    },
  }.freeze

  LINKS = [{
    href:   'csvs/all-all.csv',
    title:  'Download all results as a CSV file.',
    text:   'Download Results (CSV)',
  }, {
    href:   'https://github.com/pablotron/p4-bench',
    title:  'View code on GitHub.',
    text:   'GitHub Page',
  }].freeze

  TEMPLATES = Luigi::Cache.new({
    index: %{
      <!DOCTYPE html>
      <html lang='en'>
        <head>
          <meta charset='utf-8'/>
          <meta
            name='viewport'
            content='width=device-width, initial-scale=1, shrink-to-fit=no'
          />

          <link
            rel='stylesheet'
            type='text/css'
            href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css'
            integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T'
            crossorigin='anonymous'
          />

          <title>%{title|h}</title>
        </head>

        <body>
          <div class='container'>
            <h1>%{title|h}</h1>

            <p>
              This page contains OpenSSL benchmarks across several
              Raspberry Pis and x86-64 systems generated using the
              <code>openssl speed</code> command.
            </p>

            <ul>
              %{links}
            </ul>

            <section>
              <h2>Systems</h2>

              <p>
                Test system details.
              </p>

              %{hosts}
            </section>

            %{sections}
          </div><!-- container -->
        </body>
      </html>
    }.strip,

    all: %{
      <table class='table table-sm table-hover'>
        <thead>
          <tr>%{cols}</tr>
        </thead>

        <tbody>
          %{rows}
        </tbody>
      </table>
    }.strip,

    col: %{
      <th>%{name|h}</th>
    }.strip,

    row: %{
      <tr>%{row}</tr>
    }.strip,

    cell: %{
      <td>%{text|h}</td>
    }.strip,

    svg_title: %{
      Speed Test Results (Systems: %{arch|h}, Algorithm: %{algo|h})
    }.strip,

    svg: %{
      <img
        src='%{path|h}'
        class='img-fluid'
        title='%{name|h}'
        alt='%{name|h}'
      />
    }.strip,

    link: %{
      <li>
        <a href='%{href|h}' title='%{title|h}'>
          %{text|h}
        </a>
      </li>
    }.strip,

    section: %{
      <section>
        <h2>Results: %{name|h}</h2>
        %{text}
        %{svgs}
      </section>
    }.strip,
  })

  #
  # Background process mixin.
  #
  module BG
    #
    # Generate SSH command.
    #
    def ssh(host, cmd)
      ['/usr/bin/ssh', host, *cmd]
    end

    #
    # Spawn background task that writes standard output to given file
    # and return the PID.
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

  #
  # Process a map of hosts to background command queues in parallel.
  #
  class HostQueue
    include BG

    #
    # Allow singleton invocation.
    #
    def self.run(log, queues)
      new(log, queues).run
    end

    def initialize(log, queues)
      @log, @queues = log, queues
      @pids = {}
    end

    #
    # Block until all commands have been run successfully on all hosts,
    # or until any command on any host fails.
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
      # complete, and return HTML fragments by section
      html = save(parse_data).merge({
        # generate hosts.csv and hosts html
        hosts: make_hosts,
      })

      # save index.html
      save_index_html(html)
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
    # Spawn benchmark tasks in background and block until they are
    # complete.
    #
    def spawn_benchmarks
      # build map of hosts to commands
      queues = Hash.new { |h, k| h[k] = [] }

      # populate map
      @config['hosts'].each do |row|
        TESTS.each do |test|
          case test[:type]
          when 'algos'
            # queue test command for each algorithm
            (@config['algos'] || ALGOS).each do |algo|
              queues[row['host']] << {
                cmd: [*test[:exec], algo],
                out: '%s/hosts/%s/%s-%s.txt' % [
                  out_dir,
                  row['name'],
                  test[:name],
                  algo,
                ],
              }
            end
          else
            # queue command for test
            queues[row['host']] << {
              cmd: test[:exec],
              out: '%s/hosts/%s/%s.txt' % [
                out_dir,
                row['name'],
                test[:name],
              ]
            }
          end
        end
      end

      # block until all task queues have completed successfully
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
              4.times.map { |j|
                {
                  algo: ((j & 1) != 0) ? 'all' : algo,
                  arch: ((j & 2) != 0) ? 'all' : arch,
                }
              }.each do |agg|
                val = vals[i + 3].to_f
                max = r[agg[:arch]][agg[:algo]][:max]
                r[agg[:arch]][agg[:algo]][:max] = val if val > max

                r[agg[:arch]][agg[:algo]][:rows] << (if agg[:algo] == 'all'
                  # build row for all-*.csv
                  [row['name'], algo, size, val]
                else
                  # row for algo-specific CSV
                  [row['name'], size, val]
                end)
              end
            end
          end
        end

        r
      end
    end

    #
    # Generate CSVs, SVGs, and HTML fragments, then return map of arch
    # to HTML fragments.
    #
    def save(all_data)
      save_csvs(all_data)
      svgs = save_svgs(all_data)
      make_html(svgs)
    end

    #
    # Save all CSVs.
    #
    def save_csvs(all_data)
      all_data.each do |arch, algos|
        algos.each do |algo, data|
          save_csv(
            '%s/csvs/%s-%s.csv' % [out_dir, arch, algo],
            COLS[(algo == 'all') ? :all : :algo].map { |col| col[:id] },
            data[:rows]
          )
        end
      end
    end

    #
    # Save SVGs and return a lut of arch to svgs.
    #
    def save_svgs(all_data)
      pids = []
      svgs = Hash.new { |h, k| h[k] = [] }
      # generate svgs
      data = all_data.keys.each do |arch|
        # omit algo=all svgs because they are too large
        all_data[arch].keys.select { |algo|
          algo != 'all'
        }.each do |algo|
          # get rows
          rows = all_data[arch][algo][:rows]

          # get maximum value for plot
          max = get_max_value(all_data, arch, algo)

          # build svg data
          svg = make_svg(arch, algo, max, rows)

          # add to svg lut
          svgs[arch] << {
            algo: algo,
            path: svg[:path],
            title: svg[:title],
          }

          # save in background and add pid list of pids
          pids << save_svg(svg)
        end
      end

      # wait for background tasks to complete
      join('save_svgs', pids)

      # return svg data lut
      svgs
    end

    #
    # Generate HTML fragments for each architecture.
    #
    def make_html(svgs)
      svgs.keys.reduce({}) do |r, arch|
        r[arch] = svgs[arch].sort { |a, b|
          a[:path] <=> b[:path]
        }.map { |row|
          TEMPLATES[:svg].run({
            path: 'svgs/%s' % [File.basename(row[:path])],
            name: row[:title],
          })
        }.join

        r
      end
    end

    #
    # Generate CSV and HTML table of hosts and return generated HTML.
    #
    def make_hosts
      save_hosts_csv
      make_hosts_html
    end

    #
    # Generate out/csvs/hosts.csv and return thread.
    #
    def save_hosts_csv
      save_csv(
        '%s/csvs/hosts.csv' % [out_dir],
        COLS[:hosts].map { |col| col[:name] },
        @config['hosts'].map { |row|
          COLS[:hosts].map { |col| row[col[:id]] }
        }
      )
    end

    #
    # Generate and return hosts HTML.
    #
    def make_hosts_html
      TEMPLATES[:all].run({
        cols: COLS[:hosts].map { |col|
          TEMPLATES[:col].run(col)
        }.join,

        rows: @config['hosts'].map { |row|
          path = '%s/hosts/%s/version.txt' % [out_dir, row['name']]
          row.merge({
            'openssl' => File.read(path).strip,
          })
        }.map { |row|
          TEMPLATES[:row].run({
            row: COLS[:hosts].map { |col|
              TEMPLATES[:cell].run({
                text: row[col[:id]]
              })
            }.join
          })
        }.join,
      })
    end

    #
    # Generate and write out/index.html.
    #
    def save_index_html(html)
      File.write('%s/index.html' % [out_dir], TEMPLATES[:index].run({
        title: 'OpenSSL Benchmark Results',
        hosts: html[:hosts],

        links: LINKS.map { |row|
          TEMPLATES[:link].run(row)
        }.join,

        sections: %i{all arm x86}.map { |arch|
          TEMPLATES[:section].run({
            svgs: html[arch.to_s],
          }.merge(ARCHS[arch]))
        }.join,
      }))
    end

    #
    # Save CSV file.
    #
    def save_csv(path, cols, rows)
      CSV.open(path, 'wb') do |csv|
        # write headers
        csv << cols

        # write rows
        rows.each do |row|
          csv << row
        end
      end
    end

    #
    # Build data for SVG.
    #
    def make_svg(arch, algo, max, rows)
      {
        # build output path
        path: '%s/svgs/%s-%s.svg' % [out_dir, arch, algo],

        # build title
        title: TEMPLATES[:svg_title].run({
          arch: ARCHS[arch.intern][:name],
          algo: algo,
        }),

        # output image size (in inches)
        size: [6.4 * 2, 4.8 * 2],

        # output image DPI
        dpi: 100,

        # font sizes (in points)
        fontsize: {
          yticks: 10,
          title:  14,
        },

        # calculate xlimit (round up to nearest 50)
        xlimit: (max / (1048576 * 50.0)).ceil * 50,
        xlabel: 'Speed (MB/s)',

        # rows (sorted in reverse order)
        rows: rows.map { |row|
          [
            '%s (%d bytes)' % [row[0], row[1].to_i],
            row[2].to_f / 1048576,
          ]
        }.reverse,
      }
    end

    #
    # Render SVG in background and return SVG path, title, and PID.
    #
    def save_svg(svg)
      # invoke plot in background, return pid
      bg('/dev/null', [
        # absolute path to python
        '/usr/bin/python3',

        # build path to plot.py
        '%s/plot.py' % [__dir__],

        # build chart json data
        JSON.unparse(svg),
      ])
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
PiBench.run($0, ARGV) if __FILE__ == $0
