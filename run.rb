#!/usr/bin/env ruby

#
# run.rb: Run OpenSSL speed tests on several systems, then do
# the following:
#
#   * Aggregate results as CSV files
#   * Create SVG charts of the results
#   * Generate HTML summary of results.
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

#
# Run OpenSSL speed tests on several systems, then generate HTML, SVG,
# and CSV results.
#
# Use PiBench.run for command-line invocation.
#
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
  # (Note: sha3-256 because it is not supported in older versions of
  # openssl)
  #
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
      tip:  'System name.',
    }, {
      id:   'text',
      name: 'Description',
      tip:  'System description.',
    }, {
      id:   'architecture',
      name: 'Architecture',
      tip:  'Processor architecture.',
    }, {
      id:   'mhz',
      name: 'Speed (MHz)',
      tip:  'Maximum CPU speed, in MHz.',
    }, {
      id:   'aes',
      name: 'AES?',
      tip:  'Does this CPU have hardware-accelerated AES instructions?',
    }, {
      id:   'openssl',
      name: 'OpenSSL Version',
      tip:  'OpenSSL version.',
    }],
  }.freeze

  #
  # Architecture strings.
  #
  ARCHS = {
    all: {
      name: 'All System',
      text: %{
        <p>
          OpenSSL speed test results by algorithm across all systems.
        </p>

        <p>
          Note: The x86-64 CPUs have <a
            href='https://en.wikipedia.org/wiki/AES_instruction_set'
            title='Intel AES-NI instructions.'
          >hardware-accelerated AES (AES-NI)</a>, and the
          Raspberry Pi CPUs do not.
        </p>
      }.strip,
    },

    arm: {
      name: 'Raspberry Pi',
      text: %{
        <p>
          OpenSSL speed test results by algorithm for Raspberry Pi
          systems only.
        </p>
      }.strip,
    },

    x86: {
      name: 'x86-64',
      text: %{
        <p>
          OpenSSL speed test results, by algorithm for x86-64 systems
          only.
        </p>
      }.strip,
    },
  }.freeze

  #
  # Links in introduction of index.html.
  #
  LINKS = [{
    href:   'csvs/all-all.csv',
    title:  'Download all results as a CSV file.',
    text:   'Download Results (CSV)',
  }, {
    href:   'https://github.com/pablotron/p4-bench',
    title:  'View code on GitHub.',
    text:   'GitHub Page',
  }].freeze

  #
  # Template cache.  Used to generate index.html.
  #
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
              <h2>Test System Details</h2>

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

        <tfoot>
          <tr>
            <td colspan='%{cols|size|h}'>
              <a
                href='csvs/hosts.csv'
                title='Download test system details as a CSV.'
              >
                Download
              </a>
            </td>
          </tr>
        </tfoot>
      </table>
    }.strip,

    col: %{
      <th title='%{tip|h}'>
        %{name|h}
      </th>
    }.strip,

    row: %{
      <tr>%{row}</tr>
    }.strip,

    cell: %{
      <td title='%{tip|h}'>
        %{text|h}
      </td>
    }.strip,

    svg_title: %{
      %{arch|h} Test Results: %{algo|h}
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
        <h2>%{name|h} Test Results</h2>
        %{text}
        %{svgs}
      </section>
    }.strip,
  })

  #
  # Utility methods.
  #
  module Util
    #
    # Save CSV file.
    #
    def self.save_csv(path, cols, rows)
      ::CSV.open(path, 'wb') do |csv|
        # write headers
        csv << cols

        # write rows
        rows.each do |row|
          csv << row
        end
      end
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

      # run background task
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

    #
    # Create a new instance.
    #
    def initialize(log, queues = {})
      @log, @queues = log, queues
      @pids = {}
    end

    #
    # Block until all commands have been run successfully on all hosts,
    # or until any command on any host fails.
    #
    def run
      # start initial per-host tasks
      @queues.keys.each do |host|
        drain(host)
      end

      # loop until all tasks have been completed
      until done?
        @log.debug('HostQueue#run') do
          # log state
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
            @log.debug('HostQueue#run') do
              # log success
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

    #
    # Are all running and pending tasks complete?
    #
    def done?
      @pids.size == 0 && @queues.keys.all? { |k| @queues[k].size == 0 }
    end
  end

  #
  # Base one-shot runnable class.
  #
  class Runnable
    def self.run(model)
      new(model).run
    end

    def initialize(model)
      @model = model
    end

    def run
      raise "not implemented"
    end

    protected

    def out_dir
      @model.out_dir
    end
  end

  #
  # Fetch any needed data.
  #
  class DataFetcher < Runnable
    #
    # Create output directories and fetch any data, if needed.
    #
    def run
      # create output directories
      make_dirs

      # fetch any pending data
      fetch_data
    end

    private

    # output directories
    OUT_DIRS = %w{html csvs svgs}

    #
    # Create output directories.
    #
    def make_dirs
      dirs = (OUT_DIRS + @model.config['hosts'].map { |row|
        'hosts/%s' % [row['name']]
      }).map { |dir|
        '%s/%s' % [out_dir, dir]
      }

      @model.log.debug('make_dirs') { JSON.unparse(dirs) }
      FileUtils.mkdir_p(dirs)
    end

    #
    # Spawn tasks in background and block until they are complete.
    #
    def fetch_data
      # build map of hosts to task lists
      queues = Hash.new { |h, k| h[k] = [] }

      # populate map
      @model.config['hosts'].each do |row|
        TESTS.each do |test|
          case test[:type]
          when 'algos'
            # queue test command for each algorithm
            (@model.config['algos'] || ALGOS).each do |algo|
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
      HostQueue.run(@model.log, queues)
    end
  end

  #
  # Data parsers.
  #
  module Parsers
    #
    # Namespace for OpenSSL data parsers.
    #
    module OpenSSL
      #
      # Parse openssl benchmark data into a nested map of architecture
      # sets, algorithms, and rows.
      #
      class SpeedParser < Runnable
        def run
          @model.config['hosts'].reduce(Hash.new do |h, k|
            h[k] = Hash.new do |h2, k2|
              h2[k2] = { max: 0, rows: [] }
            end
          end) do |r, row|
            # build absolute path to openssl speed data files
            glob = '%s/hosts/%s/speed-*.txt' % [out_dir, row['name']]

            # parse speed files
            Dir[glob].each do |path|
              # get arch set (e.g. "arm" or "x86")
              arch = row['set']

              # parse file
              File.readlines(path).select { |line|
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
                    agg_arch, agg_algo = agg[:arch], agg[:algo]

                    val = vals[i + 3].to_f
                    max = r[agg_arch][agg_algo][:max]
                    r[agg_arch][agg_algo][:max] = val if val > max

                    r[agg_arch][agg_algo][:rows] << (if agg_algo == 'all'
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
      end

      #
      # Parse OpenSSL version data into a map of host to version.
      #
      class VersionParser < Runnable
        def run
          @model.config['hosts'].reduce({}) do |r, row|
            r[row['name']] = File.read('%s/hosts/%s/version.txt' % [
              out_dir,
              row['name'],
            ]).strip.split(/\s+/)[1]

            r
          end
        end
      end
    end

    #
    # Parse lscpu data and return a map of host to cpu info.
    #
    class CPUInfoParser < Runnable
      def run
        @model.config['hosts'].reduce({}) do |r, row|
          r[row['name']] = File.readlines('%s/hosts/%s/lscpu.txt' % [
            out_dir,
            row['name'],
          ]).reduce({}) do |hr, line|
            row = line.strip.split(/:\s+/)
            hr[make_key(row[0])] = row[1]

            hr
          end.tap do |h|
            h.update({
              mhz: (h['cpu-max-mhz'] || h['cpu-mhz']).to_f.round,
              aes: h['flags'] =~ /aes/ ? 'Yes' : 'No',
            })
          end

          r
        end
      end

      private

      #
      # Normalize an lscpu key.
      #
      def make_key(s)
        s.downcase
          .gsub(/\(s\)/, 's')
          .gsub(/[^a-z0-9-]+/, '-')
          .gsub(/--/, '-')
      end
    end

    #
    # Parse speed data and build an architecture to SVGs map.
    #
    class SVGDataParser < Runnable
      #
      # Build an architecture to SVG list to generate from the
      # previously-loaded speed data.
      #
      def run
        svgs = Hash.new { |h, k| h[k] = [] }

        # generate svgs
        @model.speeds.keys.each do |arch|
          # omit algo=all svgs because they are too large
          @model.speeds[arch].keys.select { |algo|
            algo != 'all'
          }.each do |algo|
            # get rows
            rows = @model.speeds[arch][algo][:rows]

            # get maximum value for plot
            max = get_max_value(arch, algo)

            # build svg data
            svg = make_svg(arch, algo, max, rows)

            # add to svg lut
            svgs[arch] << svg
          end
        end

        # return svg data lut
        svgs
      end

      private

      #
      # Build data for SVG.  This data is serialized as JSON and passed
      # to `plot.py` to generate an SVG.
      #
      def make_svg(arch, algo, max, rows)
        {
          # save arch and algo
          arch: arch,
          algo: algo,

          # build output path
          path: '%s/svgs/%s-%s.svg' % [out_dir, arch, algo],

          # build title
          title: TEMPLATES[:svg_title].run({
            arch: ARCHS[arch.intern][:name],
            algo: algo,
          }),

          # output image size (in inches)
          size: [
            6.4 * 2,
            4.8 * 2,
          ],

          # output image DPI
          dpi: 100,

          # font sizes (in points)
          fontsize: {
            yticks: 10,
            title:  14,
          },

          # calculate xlimit (round up to nearest 50)
          xlimit: (max / (1048576 * 50.0)).ceil * 50,

          # x-axis label
          xlabel: 'Speed (MB/s)',

          # rows
          rows: rows.map { |row|
            [
              '%s (%d bytes)' % [row[0], row[1].to_i],
              (row[2].to_f / 1048576).round(2),
            ]
          },
        }
      end

      #
      # get maximum value depending for chart
      #
      def get_max_value(arch, algo)
        is_aes = is_aes?(algo)

        @model.speeds['all'].keys.select { |k|
          is_aes == is_aes?(k)
        }.map { |k|
          @model.speeds[arch][k][:max]
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
    end
  end

  #
  # Fetch any data (if needed) and parse it.
  #
  class Model
    attr :config,
         :log,
         :speeds,
         :versions,
         :cpus,
         :svgs

    #
    # Create model instance based on given config.
    #
    def initialize(config, log)
      # cache config and log
      @config, @log = config, log

      # fetch data (if needed)
      DataFetcher.run(self)

      # load parsed data
      @speeds = Parsers::OpenSSL::SpeedParser.run(self)
      @versions = Parsers::OpenSSL::VersionParser.run(self)
      @cpus = Parsers::CPUInfoParser.run(self)

      # render svg data (references data loaded above)
      @svgs = Parsers::SVGDataParser.run(self)
    end

    #
    # Get output directory.
    #
    def out_dir
      @config['out_dir']
    end
  end

  #
  # View namespace.
  #
  module Views
    #
    # Speed data views namespace.
    #
    module Speed
      #
      # Save speed data as CSVs.
      #
      class CSVView < Runnable
        #
        # Save speed data as CSVs.
        #
        def run
          @model.speeds.each do |arch, algos|
            algos.each do |algo, data|
              path = '%s/csvs/%s-%s.csv' % [out_dir, arch, algo]
              cols_key = (algo == 'all') ? :all : :algo
              cols = COLS[cols_key].map { |col| col[:id] }
              Util.save_csv(path, cols, data[:rows])
            end
          end
        end
      end

      #
      # Save speed data as SVGs.
      #
      class SVGView < Runnable
        include BG

        #
        # Create an SVGView instance.
        #
        def initialize(model)
          super(model)
          @log = @model.log
        end

        #
        # Save speed data as SVGs.
        #
        def run
          pids = []

          # generate svgs
          @model.svgs.each do |arch, svgs|
            svgs.each do |svg|
              # save in background and add pid list of pids
              pids << save_svg(svg)
            end
          end

          # wait for background tasks to complete
          join(pids)
        end

        private

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
        # Join set of PIDs together.
        #
        def join(pids = [])
          @log.debug('join') { JSON.unparse({ pids: pids }) }

          # wait for all tasks to complete and check for errors
          errors = pids.reduce([]) do |r, pid|
            ::Process.wait(pid)
            $?.success? ? r : (r << pid)
          end

          # check for errors
          if errors.size > 0
            # build error message
            err = 'failed PIDs: %s' % [JSON.unparse(errors)]

            # log and raise error
            @log.fatal('join') { err }
            raise err
          end
        end
      end
    end

    #
    # Namespace for hosts views.
    #
    module Hosts
      #
      # Abstract parent class for hosts views.
      #
      class HostsView < Runnable
        protected

        #
        # Get an array of hosts and merge the `lscpu` and OpenSSL version
        # information for each host.
        #
        def hosts
          @model.config['hosts'].map { |row|
            row.merge(@model.cpus[row['name']]).merge({
              openssl: @model.versions[row['name']],
            })
          }
        end
      end

      #
      # Generate csvs/hosts.csv.
      #
      class CSVView < HostsView
        #
        # Generate csvs/hosts.csv.
        #
        def run
          Util.save_csv(
            '%s/csvs/hosts.csv' % [out_dir],
            COLS[:hosts].map { |col| col[:name] },
            hosts.map { |row|
              COLS[:hosts].map { |col|
                row[col[:id]] || row[col[:id].intern]
              }
            }
          )
        end
      end

      #
      # Generate HTML for hosts section.
      #
      class SectionView < HostsView
        #
        # Generate HTML for hosts section.
        #
        def run
          TEMPLATES[:all].run({
            cols: COLS[:hosts].map { |col|
              TEMPLATES[:col].run(col)
            }.join,

            rows: hosts.map { |row|
              TEMPLATES[:row].run({
                row: COLS[:hosts].map { |col|
                  TEMPLATES[:cell].run({
                    tip:  col[:tip] || '',
                    text: row[col[:id]] || row[col[:id].intern]
                  })
                }.join
              })
            }.join,
          })
        end
      end
    end

    #
    # Namespace for index.html views.
    #
    module Index
      #
      # Generate HTML fragment for given list of SVGs.
      #
      class SVGListView < Runnable
        #
        # Generate HTML fragment for given list of SVGs.
        #
        def run(svgs)
          svgs.sort { |a, b|
            a[:path] <=> b[:path]
          }.map { |row|
            TEMPLATES[:svg].run({
              path: 'svgs/%s' % [File.basename(row[:path])],
              name: row[:title],
            })
          }.join
        end
      end

      #
      # Generate and write out/index.html.
      #
      class HTMLView < Runnable
        # ordered list of sections symbols
        SECTIONS = %i{all arm x86}

        #
        # Create a new instance.
        #
        def initialize(model)
          super(model)

          # create/cache svg list view
          view = SVGListView.new(@model)

          # render svg lists as html
          @html = @model.svgs.reduce({
            # render hosts section
            hosts: Hosts::SectionView.run(@model),
          }) do |r, pair|
            r[pair[0].intern] = view.run(pair[1])
            r
          end
        end

        #
        # Generate and write out/index.html.
        #
        def run
          File.write('%s/index.html' % [out_dir], TEMPLATES[:index].run({
            title: 'OpenSSL Speed Test Results',
            hosts: @html[:hosts],

            # intro links
            links: LINKS.map { |row|
              TEMPLATES[:link].run(row)
            }.join,

            # sections
            sections: SECTIONS.map { |arch|
              TEMPLATES[:section].run({
                svgs: @html[arch],
              }.merge(ARCHS[arch]))
            }.join,
          }))
        end
      end
    end

    #
    # Render everything.
    #
    class FullView < Runnable
      #
      # Render everything.
      #
      def run
        # generate speed CSVs and SVGs
        Speed::CSVView.run(@model)
        Speed::SVGView.run(@model)

        # generate csvs/hosts.csv
        Hosts::CSVView.run(@model)

        # save index.html
        Index::HTMLView.run(@model)
      end
    end
  end

  #
  # Allow command-line invocation.
  #
  def self.run(app, args)
    # add global size filter
    Luigi::FILTERS[:size] = proc { |v| v.size }

    # check command-line arguments, get config path
    unless config_path = args.shift
      raise "Usage: #{app} config.yaml"
    end

    # load config
    config = Util.load_config(config_path)

    # create logger from config
    log = ::Logger.new(
      (config['log_path'] || STDERR),
      level: (config['log_level'] || 'info').intern
    )

    # create model
    model = Model.new(config, log)

    # render everything
    Views::FullView.run(model)
  end
end

# allow cli invocation
PiBench.run($0, ARGV) if __FILE__ == $0
