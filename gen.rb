#!/usr/bin/env ruby

require 'fileutils'
require 'yaml'
require 'csv'
require 'logger'

class AlgorithmTester
  # block sizes
  SIZES = %w{16 64 256 1024 8192 16384}

  TESTS = [{
    name: 'lscpu',
    exec: %w{lscpu},
  }, {
    name: 'openssl',
    exec: %w{openssl speed -mr -evp blake2b512 sha256 sha512 aes},
  }]

  CSV_COLS = {
    all:  %w{host algo size speed},
    algo: %w{host size speed},
  }

  def self.run(app, args)
    new(app, args).run
  end

  def initialize(app, args)
    @log = ::Logger.new(STDERR)

    # check command-line arguments
    unless config_path = args.shift
      raise "Usage: #{app} config.yaml"
    end

    # load config
    @config = load_config(config_path)
    log_level = (@config['log_level'] || 'info').upcase
    @log.level = Logger.const_get((@config['log_level'] || 'info').upcase)
    @log.debug { "log level = #{log_level}" }
  end

  def run
    # create output directories
    make_output_dirs

    # connect to hosts in background, wait for all to complete
    join(spawn_benchmarks)

    # generate csvs and svgs, wait for all to complete
    join(save(parse_data))
  end

  private

  #
  # Create output directories
  #
  def make_output_dirs
    dirs = (%w{csvs svgs} + @config['hosts'].map { |row|
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
    # connect to hosts in background
    @config['hosts'].reduce([]) do |r, row|
      TESTS.reduce(r) do |r, test|
        # build absolute path to output file
        out_path = '%s/hosts/%s/%s.txt' % [
          out_dir,
          row['name'],
          test[:name],
        ]

        unless File.exists?(out_path)
          # run command, append PID to results
          r << bg(out_path, ssh(row['host'], test[:exec]))
        end

        r
      end
    end
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
      # build absolute path to openssl data file
      path = '%s/hosts/%s/openssl.txt' % [out_dir, row['name']]

      # get arch
      arch = row['pi'] ? 'arm' : 'intel'

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
            max = r[agg[:algo]][agg[:arch]][:max]
            r[agg[:algo]][agg[:arch]][:max] = val if val > max

            r[agg[:algo]][agg[:arch]][:rows] << if agg[:algo] == 'all'
              # build row for all-*.csv
              [row['name'], algo, size, val]
            else
              # row for algo-specific CSV
              [row['name'], size, val]
            end
          end
        end
      end
      r
    end
  end

  #
  # save results as CSV, generate SVGs in background, and
  # return array of PIDs.
  #
  def save(data)
    data.reduce([]) do |r, pair|
      algo, arch_hash = pair

      arch_hash.reduce(r) do |r, pair|
        arch, arch_data = pair

        # save csv
        csv_path = save_csv(algo, arch, arch_data[:rows])

        if algo != 'all'
          max = get_max_value(data, algo, arch)
          r << save_svg(algo, arch, max, csv_path)
        end

        # return list of pids
        r
      end
    end
  end

  #
  # save CSV of rows.
  #
  def save_csv(algo, arch, rows)
    # build path to output csv
    csv_path = '%s/csvs/%s-%s.csv' % [out_dir, algo, arch]

    # write csv
    CSV.open(csv_path, 'wb') do |csv|
      # write column headers
      csv << CSV_COLS[(algo == 'all') ? :all : :algo]

      # write rows
      rows.each do |row|
        csv << row
      end
    end

    # return csv path
    csv_path
  end

  ARCH_TITLES = {
    all:    'OpenSSL Speed: %s, All Systems',
    arm:    'OpenSSL Speed: %s, Raspberry Pis Only',
    intel:  'OpenSSL Speed: %s, Intel Only',
  }

  #
  # Render CSV as SVG in background and return PID.
  #
  def save_svg(algo, arch, max, csv_path)
    plot_path = '%s/plot.py' % [__dir__]
    svg_path = '%s/svgs/%s-%s.svg' % [out_dir, algo, arch]

    # make chart title
    title = ARCH_TITLES[arch.intern] % [algo]

    # calculate xlimit (round up to nearest 100)
    # xlimit = ((algo =~ /^aes/) ? 400 : 2000).to_s
    xlimit = (max / 104857600.0).ceil * 100

    # build plot command
    plot_cmd = [
      '/usr/bin/python3',
      plot_path,
      csv_path,
      svg_path,
      title,
      xlimit.to_s,
    ]

    # create svg in background
    bg('/dev/null', plot_cmd)
  end

  #
  # get maximum value depending for chart
  #
  def get_max_value(data, algo, arch)
    # get aes algorithms
    aes_algos = data.keys.select { |k| k =~ /^aes-/ }

    # calculate maximum value
    max = if arch == 'all'
      data['all']['all'][:max]
    elsif aes_algos.include?(algo)
      aes_algos.map { |k|
        data[k][arch][:max]
      }.reduce(0) { |rm, v|
        v > rm ? v : rm
      }
    else 
      (data.keys - aes_algos).map { |k|
        data[k][arch][:max]
      }.reduce(0) { |rm, v|
        v > rm ? v : rm
      }
    end
  end

  #
  # Load config file and check for required keys.
  #
  def load_config(path)
    # read/check config
    YAML.load_file(path).tap do |r|
      # check for required config keys
      missing = %w{out_dir hosts}.reject { |key| r.key?(key) }
      raise "Missing required config keys: #{missing}" if missing.size > 0
    end
  end

  #
  # join set of PIDs together
  #
  def join(set_name, pids = [])
    @log.debug('join') do
      'set = %s, pids = %s' % [set_name, pids.join(', ')]
    end

    pids.each do |pid|
      Process.wait(pid)
      raise "#{set_name} #{pid} failed" unless $?.success?
    end
  end

  #
  # Generate SSH command.
  #
  def ssh(host, cmd)
    cmd = ['/usr/bin/ssh', host, *cmd]
    cmd
  end

  #
  # Spawn background task and return PID.
  #
  def bg(out_path, cmd)
    @log.debug('bg') do
      'out_path = %s, cmd = %s' % [out_path, cmd.join(' ')]
    end

    spawn(*cmd, in: '/dev/null', out: out_path, err: '/dev/null')
  end

  #
  # Get output directory.
  #
  def out_dir
    @config['out_dir']
  end
end

# allow cli invocation
AlgorithmTester.run($0, ARGV) if __FILE__ == $0
